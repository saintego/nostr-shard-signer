import type { Web3Auth } from '@web3auth/modal';
import { useEffect, useRef, useState } from 'react';
import type { BackupMethod } from '../lib/backup';
import { openEnvelopeCopies } from '../lib/envelopeStore';
import type { GlobalAccount } from '../lib/globalAccount';
import { openGlobalList } from '../lib/globalList';
import { type GlobalOptions, type GlobalResult, serveGlobalPopup } from '../lib/globalPopup';
import { format } from '../lib/i18n';
import { linkRefusal, lookUp, restrictedGrant } from '../lib/linking';
import { restoreUrl } from '../lib/masterKey';
import { afterLogin, type FlowDeps, openLinked, openOwn, type Step } from '../lib/popupFlow';
import {
  loginOnce,
  type PopupLogin,
  PROVIDERS,
  type Provider,
  prepareInstance,
} from '../lib/popupLogin';
import { publishToSignerRelays, queryRelays } from '../lib/relayPublish';
import { SHARED_SIGN_IN_CLIENT_ID } from '../lib/shared';
import { useMessages } from '../lib/useMessages';
import { AccountQuestionView } from './AccountQuestionView';
import { globalSignInMessages } from './GlobalSignInMessages';
import { LinkConfirmView } from './LinkConfirmView';
import { linkingMessages } from './LinkingMessages';
import { RestrictedView } from './RestrictedView';
import { TestVersionNotice } from './TestVersionNotice';
import { WelcomeBackView } from './WelcomeBackView';
import './GlobalSignInPopup.css';

type Reply = (result: Omit<GlobalResult, 'type'>) => void;
type AccountStep = Extract<Step, { step: 'account' }>;

type State =
  | { step: 'waiting' }
  | { step: 'refused' }
  | { step: 'ready'; site: string }
  | { step: 'working'; site: string }
  | ({ site: string } & Step)
  /** Before sealing a link: who is being linked (review 8, item 7), or why it can't be. */
  | ({ step: 'link-confirm'; site: string; candidate: PopupLogin; refused: string | null } & Omit<
      AccountStep,
      'step'
    >)
  | { step: 'failed'; site: string; reason: string }
  | { step: 'done'; site: string; broughtOver?: boolean };

/** Where the account reads and writes (relays, Evolu), and this site login's marker address. */
const flowDeps = (options: GlobalOptions): FlowDeps => ({
  openList: (root) => openGlobalList(root),
  openCopies: (owner) => openEnvelopeCopies(owner),
  query: (filter) => queryRelays(filter),
  publish: publishToSignerRelays,
  ...(options.markerAddress ? { markerAddress: options.markerAddress } : {}),
});

const hostOf = (origin: string) => {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
};

/** Why a sign-in can't be linked, for the user (review 8, items 4 and 8). */
const refusalText = (
  refusal: ReturnType<typeof linkRefusal>,
  lm: (typeof linkingMessages)['en']
) =>
  refusal === null
    ? null
    : {
        'same-login': lm.refusedSame,
        'own-account': lm.refusedOwn,
        'linked-elsewhere': lm.refusedElsewhere,
        unknown: lm.refusedUnknown,
      }[refusal];

/** The first step: Google, Apple, Facebook or X, each opening the provider's window from the click. */
function ProviderButtons({ onSignIn }: { onSignIn: (provider: Provider) => void }) {
  const m = useMessages(globalSignInMessages);
  return (
    <>
      {PROVIDERS.map((p, i) => (
        <button
          key={p}
          type="button"
          className={`np-button ${i === 0 ? 'np-filled' : 'np-outlined'}`}
          onClick={() => onSignIn(p)}
        >
          {{ google: m.google, apple: m.apple, facebook: m.facebook, twitter: m.x }[p]}
        </button>
      ))}
      <p className="np-hint">{m.providerHint}</p>
    </>
  );
}

const reasonOf = (e: unknown) => (e as Error)?.message ?? String(e);

/**
 * The signer's popup for the global sign-in (#80, #84, #98). Serves only the
 * signer's own widget (lib/globalPopup.ts), runs the global sign-in on the
 * signer's top-level storage, finds the account (its own, or another
 * account's through a link), hands the site its grant and ends the session.
 */
export function GlobalSignInPopupView() {
  const m = useMessages(globalSignInMessages);
  const lm = useMessages(linkingMessages);
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

  const wipe = () => {
    void accountRef.current?.close();
    sessionRef.current?.login.key.fill(0);
  };
  useEffect(() => {
    window.addEventListener('pagehide', wipe);
    return () => window.removeEventListener('pagehide', wipe);
  });

  useEffect(() => {
    if (!SHARED_SIGN_IN_CLIENT_ID) return;
    // Ready before the click, so the provider's window opens from it.
    w3aRef.current = prepareInstance();
    w3aRef.current.catch(() => {});
    return serveGlobalPopup(
      location.pathname,
      (site, reply, options) => {
        replyRef.current = reply;
        optionsRef.current = options;
        setState({ step: 'ready', site });
      },
      () => setState({ step: 'refused' })
    );
  }, []);

  /** One provider login, from the click; the next instance is prepared right after. */
  const login = async (provider: Provider) => {
    const instance = await (w3aRef.current ?? Promise.reject(new Error('not set up')));
    try {
      return await loginOnce(instance, provider);
    } finally {
      w3aRef.current = prepareInstance();
      w3aRef.current.catch(() => {});
    }
  };

  const run = async (site: string, step: () => Promise<void>) => {
    setBusy(true);
    try {
      await step();
    } catch (e) {
      setState({ step: 'failed', site, reason: reasonOf(e) });
    } finally {
      setBusy(false);
    }
  };

  /** Hands the site its grant (or tells it no identity is left), then wipes the root. */
  const finish = async (site: string, pubkey: string | 'none') => {
    const account = accountRef.current;
    if (!account) return;
    try {
      if (pubkey === 'none') {
        // Leaving the global account on this site: "unpaired" on own-clientId sites (D7).
        await account.leaveSite();
        replyRef.current?.({ error: 'NO_IDENTITY' });
      } else {
        const grant = await account.grant(pubkey);
        const backedUp = backedUpRef.current;
        const marker = await account.siteMarker();
        replyRef.current?.({
          grant,
          ...(backedUp ? { backedUp } : {}),
          ...(marker ? { marker } : {}),
        });
      }
      setState({ step: 'done', site });
      setTimeout(() => window.close(), 1200);
    } catch (e) {
      setState({ step: 'failed', site, reason: reasonOf(e) });
    } finally {
      accountRef.current = null;
      await account.close();
    }
  };

  /** Shows a step; an account step may finish at once (a first sign-in, or bring-over). */
  const show = async (site: string, step: Step) => {
    if (step.step !== 'account') return setState({ site, ...step });
    accountRef.current = step.account;
    const { intent, siteKey } = optionsRef.current;
    // "Use this account on other sites" (D9): stored, and the window closes.
    if (intent === 'bring-over' && siteKey) {
      await step.account.addStored(siteKey);
      replyRef.current?.({ error: 'BROUGHT_OVER' });
      setState({ step: 'done', site, broughtOver: true });
      accountRef.current = null;
      await step.account.close();
      setTimeout(() => window.close(), 2500);
      return;
    }
    const first = step.account.list[0];
    // A new account: identity 0, straight away (D8: Welcome back only for an existing account).
    if (step.account.isNew && first && intent !== 'backup') {
      await step.account.pair(first.pubkey);
      return finish(site, first.pubkey);
    }
    setState({ site, ...step });
  };

  const signIn = (site: string, provider: Provider) =>
    run(site, async () => {
      setState({ step: 'working', site });
      wipe();
      accountRef.current = null;
      const first = await login(provider);
      sessionRef.current = first;
      await show(site, await afterLogin(first, site, flowDeps(optionsRef.current)));
    });

  /** "Made one with another sign-in?": sign in with it, then link the first login to that account. */
  const linkFirstTo = (site: string, first: PopupLogin, provider: Provider) =>
    run(site, async () => {
      const second = await login(provider);
      const step = await afterLogin(second, site, flowDeps(optionsRef.current));
      if (step.step !== 'account') return setState({ site, ...step });
      sessionRef.current = second;
      accountRef.current = step.account;
      setState({ ...step, step: 'link-confirm', site, candidate: first, refused: null });
    });

  /** "Link another sign-in" in Manage: sign in with it and check it before asking (review 8). */
  const linkAnother = (site: string, current: AccountStep, provider: Provider) =>
    run(site, async () => {
      const candidate = await login(provider);
      const session = sessionRef.current;
      const found = await lookUp(candidate.login.key, flowDeps(optionsRef.current));
      await found.ownList.close().catch(() => {});
      const refusal = session ? linkRefusal(session.login, candidate.login, found) : 'unknown';
      const refused = refusalText(refusal, lm);
      setState({ ...current, step: 'link-confirm', site, candidate, refused });
    });

  /** Closing with the account open still tells the site what's left (after unpairing). */
  const close = () => {
    const account = accountRef.current;
    if (account && state.step === 'account')
      return void finish(state.site, account.paired[0]?.pubkey ?? 'none');
    wipe();
    window.close();
  };

  /** One step of the window (everything after the opener's request). */
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
        {s.step === 'ready' && <ProviderButtons onSignIn={(p) => void signIn(s.site, p)} />}
        {s.step === 'working' && <p className="np-loading">{m.working}</p>}
        {s.step === 'question' && (
          <AccountQuestionView
            step={s}
            busy={busy}
            onProvider={(p) => void linkFirstTo(s.site, s.first, p)}
            onCreate={() =>
              void run(s.site, async () =>
                show(s.site, await openOwn(s.first, s.site, flowDeps(optionsRef.current)))
              )
            }
            onRetry={() =>
              void run(s.site, async () =>
                show(s.site, await afterLogin(s.first, s.site, flowDeps(optionsRef.current)))
              )
            }
            onChooseOwn={() =>
              void run(s.site, async () =>
                show(s.site, await openOwn(s.first, s.site, flowDeps(optionsRef.current)))
              )
            }
            onChooseLinked={() =>
              s.kind === 'both' &&
              void run(s.site, async () =>
                show(
                  s.site,
                  await openLinked(s.first, s.root, s.primary, s.site, flowDeps(optionsRef.current))
                )
              )
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
                replyRef.current?.({ grant: await restrictedGrant(s.envelope, s.site, pubkey) });
                setState({ step: 'done', site: s.site });
                setTimeout(() => window.close(), 1200);
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
                await s.account.link(s.candidate.login, scope);
                s.candidate.login.key.fill(0);
                backToAccount(s);
              })
            }
            onCancel={() => backToAccount(s)}
          />
        )}
        {s.step === 'account' && (
          <WelcomeBackView
            site={s.site}
            account={s.account}
            signInProfile={s.profile}
            createdWith={s.createdWith}
            initialMode={optionsRef.current.intent === 'backup' ? 'backup' : 'choose'}
            restoreAddress={restoreUrl(new URL('.', location.href).href)}
            onBackedUp={(method) => {
              backedUpRef.current = method;
              // Asked from the widget's "Back up now": done, keep its identity.
              const active = optionsRef.current.active;
              const keep = s.account.paired.find((i) => i.pubkey === active) ?? s.account.paired[0];
              if (optionsRef.current.intent === 'backup' && keep) void finish(s.site, keep.pubkey);
            }}
            onFinish={(pubkey) => void finish(s.site, pubkey)}
            onError={(reason) => setState({ step: 'failed', site: s.site, reason })}
            onLinkProvider={(p) => void linkAnother(s.site, s, p)}
            onUnlink={(pointer) => s.account.unlink(pointer)}
          />
        )}
        {s.step === 'failed' && (
          <>
            <p className="np-message np-error">{format(m.failed, { reason: s.reason })}</p>
            <button
              type="button"
              className="np-button np-filled"
              onClick={() => setState({ step: 'ready', site: s.site })}
            >
              {m.retry}
            </button>
          </>
        )}
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
