// The widget's side of shared sign-in (#80), as a hook so App.tsx doesn't grow
// (AGENTS.md, Files): restore this site's identity from its cache, the sign-in
// sheet, and the global popup opened from the user's click in it.
import { createElement, useCallback, useState } from 'react';
import { IdentitySwitcher } from './components/IdentitySwitcher';
import { SharedSignInSheet } from './components/SharedSignInSheet';
import {
  restoreSharedSession,
  type SharedSession,
  signInFailure,
  signInGlobally,
  switchSharedIdentity,
} from './lib/sharedSignIn';
import type { KeyMaterial } from './lib/web3auth';

type View = 'login' | 'connecting';
type ParentMessage =
  | { type: 'AUTH_STATE'; loggedIn: false; pubkey: null }
  | { type: 'RESIZE'; state: 'modal' | 'button' }
  | { type: 'OPEN_NOSTR_SIGNER' };

interface Deps {
  parentOrigin: string;
  nostrSigner: 'bunker' | 'extension' | null;
  poweredBy: boolean;
  onSignedIn: (km: KeyMaterial) => Promise<void>;
  setView: (view: View) => void;
  postToParent: (msg: ParentMessage) => void;
  onError: (title: string, message: string, code: string) => void;
  /** Sign out on this site (the user unpaired every identity from it). */
  onSignOut: () => void;
}

export function useSharedSignIn({
  parentOrigin,
  nostrSigner,
  poweredBy,
  onSignedIn,
  setView,
  postToParent,
  onError,
  onSignOut,
}: Deps) {
  const [sheetOpen, setSheetOpen] = useState(false);
  // What this site's cache holds: its identities and the active one (#84).
  const [session, setSession] = useState<SharedSession | null>(null);
  const signedIn = useCallback(
    async (s: SharedSession) => {
      setSession(s);
      await onSignedIn(s.km);
    },
    [onSignedIn]
  );

  const showButton = useCallback(() => {
    setSheetOpen(false);
    setView('login');
    postToParent({ type: 'RESIZE', state: 'button' });
  }, [setView, postToParent]);

  /** At load: this site's cache, or the Sign in button. */
  const restore = useCallback(
    async (isCancelled: () => boolean) => {
      const restored = await restoreSharedSession();
      if (isCancelled()) return;
      if (restored) await signedIn(restored);
      else {
        setView('login');
        postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
      }
    },
    [signedIn, setView, postToParent]
  );

  /** Shows the sheet (the widget's Sign in, or the page's NostrBridge.login()). */
  const openSheet = useCallback(() => {
    setSheetOpen(true);
    postToParent({ type: 'RESIZE', state: 'modal' });
  }, [postToParent]);

  /**
   * "Continue with Google", and "Add or manage identities": runs in the click,
   * so the popup may open. A failed manage keeps the current session.
   */
  const google = useCallback(async () => {
    const pending = signInGlobally(parentOrigin);
    const managing = session !== null;
    setSheetOpen(false);
    if (!managing) {
      setView('connecting');
      postToParent({ type: 'RESIZE', state: 'button' });
    }
    try {
      await signedIn(await pending);
    } catch (e) {
      const failure = signInFailure((e as Error).message ?? '');
      if (failure === 'sign-out') return onSignOut();
      if (!managing) showButton();
      if (failure !== 'quiet') onError(failure.title, failure.message, failure.code);
    }
  }, [parentOrigin, session, signedIn, setView, postToParent, showButton, onError, onSignOut]);

  /** Another identity of this site (D14): the page sees it through onAuthChange. */
  const switchTo = useCallback(
    async (pubkey: string) => {
      const next = await switchSharedIdentity(pubkey);
      if (next) await signedIn(next);
    },
    [signedIn]
  );

  const sheet = sheetOpen
    ? createElement(SharedSignInSheet, {
        nostrSigner,
        poweredBy,
        onGoogle: () => void google(),
        onNostrSigner: () => {
          showButton();
          postToParent({ type: 'OPEN_NOSTR_SIGNER' });
        },
        onCancel: showButton,
      })
    : null;

  const switcher = session
    ? createElement(IdentitySwitcher, {
        identities: session.cache.identities,
        active: session.cache.active,
        onSwitch: (pubkey: string) => void switchTo(pubkey),
        onManage: () => void google(),
      })
    : null;

  /** Signed out on this site: forget what the cache held. */
  const forget = useCallback(() => setSession(null), []);

  return { restore, openSheet, sheet, switcher, forget };
}
