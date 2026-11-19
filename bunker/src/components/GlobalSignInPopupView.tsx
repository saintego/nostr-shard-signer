import { useEffect, useRef, useState } from 'react';
import type { Web3Auth } from '@web3auth/modal';
import { format } from '../lib/i18n';
import { useMessages } from '../lib/useMessages';
import { serveGlobalPopup, type GlobalResult } from '../lib/globalPopup';
import { grantForSite } from '../lib/identity';
import { SHARED_CLIENT_ID } from '../lib/shared';
import { extractKey, initWeb3Auth, loginWith } from '../lib/web3auth';
import { endSession, GLOBAL_SESSION, sweepGlobalSession } from '../lib/web3authSession';
import { globalSignInMessages } from './GlobalSignInMessages';
import './GlobalSignInPopup.css';

type Reply = (result: Omit<GlobalResult, 'type'>) => void;

type State =
  | { step: 'waiting' }
  | { step: 'refused' }
  | { step: 'ready'; site: string }
  | { step: 'working'; site: string }
  | { step: 'failed'; site: string; reason: string }
  | { step: 'done'; site: string };

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

  useEffect(() => {
    if (!SHARED_CLIENT_ID) return;
    // A leftover global session first (#79), then a fresh instance, ready
    // before the click so Google's window opens from it.
    w3aRef.current = sweepGlobalSession().then(() => initWeb3Auth(SHARED_CLIENT_ID, GLOBAL_SESSION));
    w3aRef.current.catch(() => {});
    return serveGlobalPopup(
      location.pathname,
      (site, reply) => {
        replyRef.current = reply;
        setState({ step: 'ready', site });
      },
      () => setState({ step: 'refused' })
    );
  }, []);

  const signIn = async (site: string) => {
    setState({ step: 'working', site });
    let w3a: Web3Auth | null = null;
    try {
      const instance = await (w3aRef.current ?? Promise.reject(new Error('not set up')));
      w3a = instance;
      await loginWith(instance, 'google');
      const login = await extractKey(instance);
      const grant = await grantForSite(login.privateKeyBytes, site);
      replyRef.current?.(grant);
      setState({ step: 'done', site });
      setTimeout(() => window.close(), 1200);
    } catch (e) {
      setState({ step: 'failed', site, reason: (e as Error)?.message ?? String(e) });
    } finally {
      // The global session ends right after use, whatever happened (#73 D23).
      const instance = w3a;
      await endSession(instance ? () => instance.logout() : null, GLOBAL_SESSION);
    }
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
          <button type="button" className="np-button np-filled" onClick={() => void signIn(state.site)}>
            {m.google}
          </button>
        )}
        {state.step === 'working' && <p className="np-loading">{m.working}</p>}
        {state.step === 'failed' && (
          <>
            <p className="np-message np-error">{format(m.failed, { reason: state.reason })}</p>
            <button type="button" className="np-button np-filled" onClick={() => void signIn(state.site)}>
              {m.retry}
            </button>
          </>
        )}
        {state.step === 'done' && <p className="np-message np-success">{format(m.done, { site })}</p>}
      </>
    );
  }

  return (
    <main className="global-popup np-app">
      <h1 className="np-title">{m.title}</h1>
      {body}
      <button type="button" className="np-button np-text global-close" onClick={() => window.close()}>
        {m.close}
      </button>
    </main>
  );
}
