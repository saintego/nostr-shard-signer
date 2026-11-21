import type { Web3Auth } from '@web3auth/modal';
import { useEffect, useRef, useState } from 'react';
import type { BackupMethod } from '../lib/backup';
import {
  type AccountDeps,
  type GlobalAccount,
  type NewProfile,
  openGlobalAccount,
} from '../lib/globalAccount';
import { openGlobalList } from '../lib/globalList';
import { type GlobalOptions, type GlobalResult, serveGlobalPopup } from '../lib/globalPopup';
import { format } from '../lib/i18n';
import { restoreUrl } from '../lib/masterKey';
import { publishToSignerRelays, queryRelays } from '../lib/relayPublish';
import { SHARED_CLIENT_ID } from '../lib/shared';
import { useMessages } from '../lib/useMessages';
import { extractKey, initWeb3Auth, loginWith } from '../lib/web3auth';
import { endSession, GLOBAL_SESSION, sweepGlobalSession } from '../lib/web3authSession';
import { globalSignInMessages } from './GlobalSignInMessages';
import { WelcomeBackView } from './WelcomeBackView';
import './GlobalSignInPopup.css';

type Reply = (result: Omit<GlobalResult, 'type'>) => void;
/** Web3Auth's names for Google, Apple and X. */
type Provider = 'google' | 'apple' | 'twitter';

type State =
  | { step: 'waiting' }
  | { step: 'refused' }
  | { step: 'ready'; site: string }
  | { step: 'working'; site: string }
  | { step: 'account'; site: string; account: GlobalAccount; profile: NewProfile | null }
  | { step: 'failed'; site: string; reason: string }
  | { step: 'done'; site: string; broughtOver?: boolean };

/** The sign-in account's name and picture, offered for new identities (D15). */
const profileOf = (info: { name?: string; profileImage?: string } | null): NewProfile | null =>
  info ? { name: info.name || undefined, picture: info.profileImage || undefined } : null;

/** Where the account reads and writes (relays, Evolu), and this site login's marker address. */
const accountDeps = (options: GlobalOptions): AccountDeps => ({
  openList: (root) => openGlobalList(root),
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

/**
 * The signer's popup for the global sign-in (#80). Serves only the signer's own
 * widget (lib/globalPopup.ts), runs the global Web3Auth sign-in on the
 * signer's top-level storage, hands the site its grant and ends the session.
 */
export function GlobalSignInPopupView() {
  const m = useMessages(globalSignInMessages);
  const [state, setState] = useState<State>({ step: 'waiting' });
  const replyRef = useRef<Reply | null>(null);
  const w3aRef = useRef<Promise<Web3Auth> | null>(null);
  // The open account holds the root: wiped when finished or when the window goes.
  const accountRef = useRef<GlobalAccount | null>(null);
  // What the widget asked for (sign in or back up) and its active identity.
  const optionsRef = useRef<GlobalOptions>({});
  // Set when the user saved a backup here (#87), sent with the grant.
  const backedUpRef = useRef<BackupMethod | undefined>(undefined);
  useEffect(() => {
    const wipe = () => void accountRef.current?.close();
    window.addEventListener('pagehide', wipe);
    return () => window.removeEventListener('pagehide', wipe);
  }, []);

  useEffect(() => {
    if (!SHARED_CLIENT_ID) return;
    // A leftover global session first (#79), then a fresh instance, ready
    // before the click so Google's window opens from it.
    w3aRef.current = sweepGlobalSession().then(() =>
      initWeb3Auth(SHARED_CLIENT_ID, GLOBAL_SESSION)
    );
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
      setState({ step: 'failed', site, reason: (e as Error)?.message ?? String(e) });
    } finally {
      accountRef.current = null;
      await account.close();
    }
  };

  /** D9: the site-only account becomes a stored identity; the widget is told, then the window closes. */
  const bringOver = async (site: string, account: GlobalAccount, siteKey: string) => {
    try {
      await account.addStored(siteKey);
      replyRef.current?.({ error: 'BROUGHT_OVER' });
      setState({ step: 'done', site, broughtOver: true });
      setTimeout(() => window.close(), 2500);
    } finally {
      accountRef.current = null;
      await account.close();
    }
  };

  const signIn = async (site: string, provider: Provider) => {
    setState({ step: 'working', site });
    const previous = accountRef.current; // a retry after a failure
    accountRef.current = null;
    await previous?.close();
    let w3a: Web3Auth | null = null;
    try {
      const instance = await (w3aRef.current ?? Promise.reject(new Error('not set up')));
      w3a = instance;
      await loginWith(instance, provider);
      const login = await extractKey(instance);
      const profile = profileOf(await instance.getUserInfo().catch(() => null));
      // The global session ends right after use (#73 D23); the root stays in this window's memory.
      await endSession(() => instance.logout(), GLOBAL_SESSION);
      w3a = null;
      const account = await openGlobalAccount(
        login.privateKeyBytes,
        site,
        accountDeps(optionsRef.current)
      );
      accountRef.current = account;
      const { intent, siteKey } = optionsRef.current;
      // "Use this account on other sites" (D9): stored, and the window closes.
      if (intent === 'bring-over' && siteKey) return await bringOver(site, account, siteKey);
      const first = account.list[0];
      // A first sign-in: identity 0, straight away (D8: Welcome back only for an existing account).
      if (account.isNew && first && intent !== 'backup') {
        await account.pair(first.pubkey);
        return await finish(site, first.pubkey);
      }
      setState({ step: 'account', site, account, profile });
    } catch (e) {
      setState({ step: 'failed', site, reason: (e as Error)?.message ?? String(e) });
    } finally {
      // Whatever happened, no global session is left behind (#73 D23).
      const instance = w3a;
      if (instance) await endSession(() => instance.logout(), GLOBAL_SESSION);
    }
  };

  /** Closing with the account open still tells the site what's left (after unpairing). */
  const close = () => {
    const account = accountRef.current;
    if (account && state.step === 'account')
      return void finish(state.site, account.paired[0]?.pubkey ?? 'none');
    window.close();
  };

  let body: React.ReactNode;
  if (!SHARED_CLIENT_ID) body = <p className="np-message np-info">{m.notSetUp}</p>;
  else if (state.step === 'waiting') body = <p className="np-loading">{m.waiting}</p>;
  else if (state.step === 'refused') body = <p className="np-message np-error">{m.refused}</p>;
  else {
    const site = hostOf(state.site);
    body = (
      <>
        <p className="global-site np-badge np-primary">{format(m.forSite, { site })}</p>
        <p className="global-explain">{format(m.explain, { site })}</p>
        {state.step === 'ready' && (
          <>
            <button
              type="button"
              className="np-button np-filled"
              onClick={() => void signIn(state.site, 'google')}
            >
              {m.google}
            </button>
            <button
              type="button"
              className="np-button np-outlined"
              onClick={() => void signIn(state.site, 'apple')}
            >
              {m.apple}
            </button>
            <button
              type="button"
              className="np-button np-outlined"
              onClick={() => void signIn(state.site, 'twitter')}
            >
              {m.x}
            </button>
            <p className="np-hint">{m.providerHint}</p>
          </>
        )}
        {state.step === 'working' && <p className="np-loading">{m.working}</p>}
        {state.step === 'account' && (
          <WelcomeBackView
            site={state.site}
            account={state.account}
            signInProfile={state.profile}
            initialMode={optionsRef.current.intent === 'backup' ? 'backup' : 'choose'}
            restoreAddress={restoreUrl(new URL('.', location.href).href)}
            onBackedUp={(method) => {
              backedUpRef.current = method;
              // Asked from the widget's "Back up now": done, keep its identity.
              const active = optionsRef.current.active;
              const keep =
                state.account.paired.find((i) => i.pubkey === active) ?? state.account.paired[0];
              if (optionsRef.current.intent === 'backup' && keep)
                void finish(state.site, keep.pubkey);
            }}
            onFinish={(pubkey) => void finish(state.site, pubkey)}
            onError={(reason) => setState({ step: 'failed', site: state.site, reason })}
          />
        )}
        {state.step === 'failed' && (
          <>
            <p className="np-message np-error">{format(m.failed, { reason: state.reason })}</p>
            <button
              type="button"
              className="np-button np-filled"
              onClick={() => setState({ step: 'ready', site: state.site })}
            >
              {m.retry}
            </button>
          </>
        )}
        {state.step === 'done' && (
          <p className="np-message np-success">
            {format(state.broughtOver ? m.broughtOver : m.done, { site })}
          </p>
        )}
      </>
    );
  }

  return (
    <main className="global-popup np-app">
      <h1 className="np-title">{m.title}</h1>
      {body}
      <button type="button" className="np-button np-text global-close" onClick={close}>
        {m.close}
      </button>
    </main>
  );
}
