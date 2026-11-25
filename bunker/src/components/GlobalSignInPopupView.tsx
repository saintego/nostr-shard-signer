import type { Web3Auth } from '@web3auth/modal';
import { useEffect, useRef, useState } from 'react';
import { timed, withTimeout } from '../lib/backgroundWrites';
import type { BackupMethod } from '../lib/backup';
import type { GlobalAccount } from '../lib/globalAccount';
import { type GlobalOptions, serveGlobalPopup } from '../lib/globalPopup';
import { format } from '../lib/i18n';
import { fromHanded } from '../lib/inlineSignIn';
import { halfDoneLink, linkRefusal, lookUp, restrictedGrant } from '../lib/linking';
import { restoreUrl } from '../lib/masterKey';
import { accountNext, afterLogin, openLinked, openOwn, type Step } from '../lib/popupFlow';
import { type Choice, loginOnce, type PopupLogin, prepareInstance } from '../lib/popupLogin';
import { SHARED_SIGN_IN_CLIENT_ID } from '../lib/shared';
import { assertSharedSignInAllowed, CANARY_PAUSED } from '../lib/sharedCanary';
import { useMessages } from '../lib/useMessages';
import { closeAfterWrites, depsFor, writes } from '../lib/windowWrites';
import { AccountQuestionView } from './AccountQuestionView';
import { globalSignInMessages } from './GlobalSignInMessages';
import {
  type AccountStep,
  hostOf,
  type Reply,
  reasonOf,
  STEP_MAX_MS,
  type State,
} from './globalSignInState';
import { LinkConfirmView, refusalText } from './LinkConfirmView';
import { linkingMessages } from './LinkingMessages';
import { NewAccountView } from './NewAccountView';
import { RestrictedView } from './RestrictedView';
import { choicesFor, type Phase, SignInChoice, StepFooter, Working } from './SignInChoice';
import { StoredBackupView } from './StoredBackupView';
import { TestVersionNotice } from './TestVersionNotice';
import { WelcomeBackView } from './WelcomeBackView';
import './GlobalSignInPopup.css';

/**
 * The signer's popup for the global sign-in (#80, #84, #98). Serves only the
 * signer's own widget (lib/globalPopup.ts), runs the global sign-in on the
 * signer's top-level storage, finds the account (its own, or another
 * account's through a link), hands the site its grant and ends the session.
 */
export function GlobalSignInPopupView() {
  const m = useMessages(globalSignInMessages);
  const lm = useMessages(linkingMessages);
  const phaseText = (phase: Phase) =>
    ({ login: m.phaseLogin, checking: m.phaseChecking, saving: m.phaseSaving })[phase];
  const phaseError = (phase: Phase) => format(m.timedOut, { phase: phaseText(phase) });
  const [state, setState] = useState<State>({ step: 'waiting' });
  const [busy, setBusy] = useState(false);
  const replyRef = useRef<Reply | null>(null);
  const w3aRef = useRef<Promise<Web3Auth> | null>(null);
  // The open account holds the root: wiped when finished or when the window goes.
  const accountRef = useRef<GlobalAccount | null>(null);
  // The login this session signed in with (linking refuses it as a second login).
  const sessionRef = useRef<PopupLogin | null>(null);
  // What the widget asked for (sign in, back up, bring over) and its active identity.
  const optionsRef = useRef<GlobalOptions>({});
  // Set when the user saved a backup here (#87), sent with the grant.
  const backedUpRef = useRef<BackupMethod | undefined>(undefined);
  /** A bring-over waits for its backup or skip (#137). */
  const bringOverRef = useRef(false);

  // The account screen last shown: where Back goes after an error there.
  const lastAccountRef = useRef<Extract<State, { step: 'account' }> | null>(null);
  useEffect(() => {
    if (state.step === 'account') lastAccountRef.current = state;
    else if (state.step === 'ready' || state.step === 'done') lastAccountRef.current = null;
  }, [state]);

  const wipe = () => {
    void accountRef.current?.close();
    sessionRef.current?.login.key.fill(0);
  };
  useEffect(() => {
    window.addEventListener('pagehide', wipe);
    return () => window.removeEventListener('pagehide', wipe);
  });

  // biome-ignore lint/correctness/useExhaustiveDependencies: once, on opening; continueFrom only uses refs and state setters
  useEffect(() => {
    if (!SHARED_SIGN_IN_CLIENT_ID) return;
    // Ready before the click, so the provider's window opens from it.
    w3aRef.current = prepareInstance(document.documentElement.lang);
    w3aRef.current.catch(() => {});
    return serveGlobalPopup(
      location.pathname,
      (site, reply, options) => {
        replyRef.current = reply;
        optionsRef.current = options;
        // The widget already signed in (#122): continue from its login.
        if (options.login) return void continueFrom(site, fromHanded(options.login));
        setState({ step: 'ready', site });
      },
      () => setState({ step: 'refused' })
    );
  }, []);

  /** One login (Web3Auth's panel, or a provider's window); the next instance is prepared right after. */
  const login = async (choice: Choice) => {
    const instance = await (w3aRef.current ?? Promise.reject(new Error('not set up')));
    // Web3Auth's panel covers the window only while a login is open (#125).
    document.body.classList.add('w3a-open');
    try {
      return await loginOnce(instance, choice);
    } finally {
      document.body.classList.remove('w3a-open');
      w3aRef.current = prepareInstance(document.documentElement.lang);
      w3aRef.current.catch(() => {});
    }
  };
  /** The login, or null when its panel or window was closed without signing in (not an error). */
  const loginOrCancel = (choice: Choice) =>
    login(choice).catch((e: unknown) => {
      if (/cancel|closed by the user|5114/i.test(reasonOf(e))) return null;
      throw e;
    });

  const run = async (site: string, step: () => Promise<void>) => {
    setBusy(true);
    try {
      await step();
    } catch (e) {
      setState({
        step: 'failed',
        site,
        reason: reasonOf(e) === CANARY_PAUSED ? m.paused : reasonOf(e),
      });
    } finally {
      setBusy(false);
    }
  };

  /** Answers the widget; false, and says so, when its frame changed since it asked (#144). */
  const send = (site: string, result: Parameters<Reply>[0]) => {
    if (replyRef.current?.(result)) return true;
    setState({ step: 'failed', site, reason: m.openerChanged });
    return false;
  };

  /** Hands the site its grant (or tells it no identity is left), then wipes the root. */
  const finish = async (site: string, pubkey: string | 'none') => {
    const account = accountRef.current;
    if (!account) return;
    setState({ step: 'working', site, phase: 'saving' });
    try {
      if (pubkey === 'none') {
        // Leaving the global account on this site: "unpaired" on own-clientId sites (D7).
        await account.leaveSite();
        if (!send(site, { error: 'NO_IDENTITY' })) return;
      } else {
        const grant = await withTimeout(account.grant(pubkey), STEP_MAX_MS, phaseError('saving'));
        const backedUp = backedUpRef.current;
        const marker = await account.siteMarker();
        const reply = { grant, ...(backedUp ? { backedUp } : {}), ...(marker ? { marker } : {}) };
        if (!send(site, reply)) return;
      }
      setState({ step: 'done', site });
      closeAfterWrites(1200);
    } catch (e) {
      setState({ step: 'failed', site, reason: reasonOf(e) });
    } finally {
      accountRef.current = null;
      // Its writes sync to Evolu's relay before the window closes (#110).
      writes.track(account.close());
    }
  };

  /** The bring-over is done (backed up or skipped): tell the site, and close. */
  const broughtOver = (site: string, account: GlobalAccount) => {
    bringOverRef.current = false;
    accountRef.current = null;
    writes.track(account.close());
    if (!send(site, { error: 'BROUGHT_OVER' })) return;
    setState({ step: 'done', site, broughtOver: true });
    closeAfterWrites(2500);
  };

  /** A new account's identity 0: paired, then its name and picture asked about (D15), if any. */
  const newAccount = async (site: string, step: AccountStep, pubkey: string) => {
    await step.account.pair(pubkey);
    const profile = step.profile;
    // Offered only when the identity has no profile yet, on relays that answered (#136).
    if (!profile || !(profile.name || profile.picture) || !(await step.account.profileFree(pubkey)))
      return finish(site, pubkey);
    setState({ step: 'new-account', site, account: step.account, profile, pubkey });
  };

  /** Shows a step; an account step may finish at once (a first sign-in, or bring-over). */
  const show = async (site: string, step: Step) => {
    if (step.step !== 'account') return setState({ site, ...step });
    accountRef.current = step.account;
    const next = accountNext(step.account, optionsRef.current);
    if (next.kind === 'bring-over') {
      await step.account.addStored(next.siteKey);
      bringOverRef.current = true;
      return setState({ ...step, step: 'stored-backup', site });
    }
    if (next.kind === 'new') return newAccount(site, step, next.pubkey);
    if (next.kind === 'pair') await step.account.pair(next.pubkey);
    if (next.kind === 'finish' || next.kind === 'pair') return finish(site, next.pubkey);
    setState({ site, ...step });
  };

  const signIn = (site: string, choice: Choice) =>
    run(site, async () => {
      setState({ step: 'working', site, phase: 'login' });
      wipe();
      accountRef.current = null;
      await assertSharedSignInAllowed(); // the canary (#91)
      const first = await timed('provider login', loginOrCancel(choice));
      if (!first) return setState({ step: 'ready', site });
      await continueFrom(site, first);
    });

  /** After a login (made here, or handed over by the widget): look the account up and show it. */
  const continueFrom = (site: string, first: PopupLogin) =>
    run(site, async () => {
      sessionRef.current = first;
      setState({ step: 'working', site, phase: 'checking' });
      const step = await timed(
        'account lookup',
        withTimeout(
          afterLogin(first, site, depsFor(optionsRef.current)),
          STEP_MAX_MS,
          phaseError('checking')
        )
      );
      await timed('account step', show(site, step));
    });

  /** "Made one with another sign-in?": sign in with it, then link the first login to that account. */
  const linkFirstTo = (site: string, first: PopupLogin, provider: Choice) =>
    run(site, async () => {
      const second = await loginOrCancel(provider);
      if (!second) return;
      setState({ step: 'working', site, phase: 'checking' });
      const step = await withTimeout(
        afterLogin(second, site, depsFor(optionsRef.current)),
        STEP_MAX_MS,
        phaseError('checking')
      );
      if (step.step !== 'account') return setState({ site, ...step });
      sessionRef.current = second;
      accountRef.current = step.account;
      setState({ ...step, step: 'link-confirm', site, candidate: first, refused: null });
    });

  /** "Link another sign-in" in Manage: sign in with it and check it before asking (review 8). */
  const linkAnother = (site: string, current: AccountStep, provider: Choice) =>
    run(site, async () => {
      const candidate = await loginOrCancel(provider);
      if (!candidate) return;
      const session = sessionRef.current;
      setState({ step: 'working', site, phase: 'checking' });
      const found = await withTimeout(
        lookUp(candidate.login.key, depsFor(optionsRef.current)),
        STEP_MAX_MS,
        phaseError('checking')
      );
      await found.ownList.close(0).catch(() => {}); // only read here
      // An envelope that already opens this account: a link left half-done, linked again.
      const half = halfDoneLink(found, current.account.isRoot);
      const refusal = session
        ? linkRefusal(session.login, candidate.login, found, half?.root)
        : 'unknown';
      const refused = refusalText(refusal, lm);
      setState({
        ...current,
        step: 'link-confirm',
        site,
        candidate,
        refused,
        ...(half ? { after: half.version } : {}),
      });
    });

  /** Runs a flow step with this window's dependencies, then shows where it leads. */
  const next = (site: string, step: (deps: ReturnType<typeof depsFor>) => Promise<Step>) =>
    void run(site, async () => show(site, await step(depsFor(optionsRef.current))));

  /** Closing with the account open still tells the site what's left (after unpairing). */
  const close = () => {
    const account = accountRef.current;
    // Closing at the backup step after a bring-over counts as skipping it (#137).
    if (account && bringOverRef.current && 'site' in state) return broughtOver(state.site, account);
    if (account && state.step === 'new-account') return void finish(state.site, state.pubkey);
    if (account && state.step === 'account')
      return void finish(state.site, account.paired[0]?.pubkey ?? 'none');
    wipe();
    closeAfterWrites(0);
  };

  /** One step of the window (everything after the opener's request). */
  // Web3Auth's panel by default; the signer's own buttons when the page asked (#113).
  const choices = choicesFor(optionsRef.current.ui === 'buttons' ? 'buttons' : 'panel');
  // With the panel, it opens by itself once: the provider's window opens from a click in it.
  const panelOpened = useRef(false);
  useEffect(() => {
    if (state.step !== 'ready' || choices[0] !== 'panel' || panelOpened.current) return;
    panelOpened.current = true;
    void signIn(state.site, 'panel');
  });
  const renderStep = (s: Exclude<State, { step: 'waiting' } | { step: 'refused' }>) => {
    const site = hostOf(s.site);
    const backToAccount = (from: Omit<AccountStep, 'step'>) =>
      setState({
        step: 'account',
        site: s.site,
        account: from.account,
        profile: from.profile,
        createdWith: from.createdWith,
      });
    return (
      <>
        <p className="global-site np-badge np-primary">{format(m.forSite, { site })}</p>
        <p className="global-explain">{format(m.explain, { site })}</p>
        {s.step === 'ready' && (
          <SignInChoice choices={choices} onSignIn={(c) => void signIn(s.site, c)} />
        )}
        {s.step === 'working' && <Working phase={s.phase} />}
        {s.step === 'new-account' && (
          <NewAccountView
            profile={s.profile}
            busy={busy}
            onContinue={(useProfile) =>
              void run(s.site, async () => {
                if (useProfile) await s.account.publishProfile(s.pubkey, s.profile);
                await finish(s.site, s.pubkey);
              })
            }
          />
        )}
        {s.step === 'question' && (
          <AccountQuestionView
            step={s}
            busy={busy}
            onProvider={(p) => void linkFirstTo(s.site, s.first, p)}
            choices={choices}
            onCreate={() =>
              next(s.site, (d) =>
                openOwn(s.first, s.site, d, s.kind === 'none' ? 'none' : undefined)
              )
            }
            onRetry={() => next(s.site, (d) => afterLogin(s.first, s.site, d))}
            onChooseOwn={() => next(s.site, (d) => openOwn(s.first, s.site, d, 'existing'))}
            onChooseLinked={() =>
              s.kind === 'both' &&
              next(s.site, (d) => openLinked(s.first, s.root, s.primary, s.site, d, s.version))
            }
          />
        )}
        {s.step === 'restricted' && (
          <RestrictedView
            envelope={s.envelope}
            site={site}
            busy={busy}
            onUse={(pubkey) =>
              void run(s.site, async () => {
                if (!send(s.site, { grant: await restrictedGrant(s.envelope, s.site, pubkey) }))
                  return;
                setState({ step: 'done', site: s.site });
                closeAfterWrites(1200);
              })
            }
          />
        )}
        {s.step === 'unlinked' && (
          <p className="np-message np-error">
            {format(lm.unlinkedOn, { date: s.date.slice(0, 10) })}
          </p>
        )}
        {s.step === 'link-confirm' && (
          <LinkConfirmView
            refused={s.refused}
            provider={s.candidate.login.provider}
            masked={s.candidate.login.masked}
            primary={s.account.primary}
            identities={s.account.list}
            busy={busy}
            onConfirm={(scope) =>
              void run(s.site, async () => {
                setState({ step: 'working', site: s.site, phase: 'saving' });
                await withTimeout(
                  s.account.link(s.candidate.login, scope, s.after),
                  STEP_MAX_MS,
                  phaseError('saving')
                );
                s.candidate.login.key.fill(0);
                backToAccount(s);
              })
            }
            onCancel={() => backToAccount(s)}
          />
        )}
        {s.step === 'stored-backup' && (
          <StoredBackupView
            onBackUp={() => setState({ ...s, step: 'account' })}
            onSkip={() => broughtOver(s.site, s.account)}
          />
        )}
        {s.step === 'account' && (
          <WelcomeBackView
            site={s.site}
            account={s.account}
            signInProfile={s.profile}
            createdWith={s.createdWith}
            initialMode={
              bringOverRef.current
                ? 'backup'
                : (({ backup: 'backup', manage: 'manage' } as const)[
                    optionsRef.current.intent as 'backup' | 'manage'
                  ] ?? 'choose')
            }
            restoreAddress={restoreUrl(new URL('.', location.href).href)}
            onBackedUp={(method) => {
              if (bringOverRef.current) return broughtOver(s.site, s.account);
              backedUpRef.current = method;
              // Asked from the widget's "Back up now": done, keep its identity.
              const active = optionsRef.current.active;
              const keep = s.account.paired.find((i) => i.pubkey === active) ?? s.account.paired[0];
              if (optionsRef.current.intent === 'backup' && keep) void finish(s.site, keep.pubkey);
            }}
            onFinish={(pubkey) => void finish(s.site, pubkey)}
            onError={(reason) => setState({ step: 'failed', site: s.site, reason })}
            onLinkProvider={(p) => void linkAnother(s.site, s, p)}
            choices={choices}
            onUnlink={(pointer) => s.account.unlink(pointer)}
          />
        )}
        <StepFooter
          step={s.step}
          reason={s.step === 'failed' ? s.reason : ''}
          busy={busy}
          toAccount={lastAccountRef.current !== null}
          onBack={() =>
            setState(
              (s.step === 'failed' && lastAccountRef.current) || { step: 'ready', site: s.site }
            )
          }
        />
        {s.step === 'done' && (
          <p className="np-message np-success">
            {format(s.broughtOver ? m.broughtOver : m.done, { site })}
          </p>
        )}
      </>
    );
  };

  let body: React.ReactNode;
  if (!SHARED_SIGN_IN_CLIENT_ID) body = <p className="np-message np-info">{m.notSetUp}</p>;
  else if (state.step === 'waiting') body = <p className="np-loading">{m.waiting}</p>;
  else if (state.step === 'refused') body = <p className="np-message np-error">{m.refused}</p>;
  else body = renderStep(state);

  return (
    <main className="global-popup np-app">
      <h1 className="np-title">{m.title}</h1>
      <TestVersionNotice />
      {body}
      <button type="button" className="np-button np-text global-close" onClick={close}>
        {m.close}
      </button>
    </main>
  );
}
