// The widget's side of shared sign-in (#80), as a hook so App.tsx doesn't grow
// (AGENTS.md, Files): restore this site's identity from its cache, the sign-in
// sheet, and the global popup opened from the user's click in it.
import { createElement, useCallback, useState } from 'react';
import { SharedSignInSheet } from './components/SharedSignInSheet';
import { restoreSharedSession, signInGlobally } from './lib/sharedSignIn';
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
}

export function useSharedSignIn({ parentOrigin, nostrSigner, poweredBy, onSignedIn, setView, postToParent, onError }: Deps) {
  const [sheetOpen, setSheetOpen] = useState(false);

  const showButton = useCallback(() => {
    setSheetOpen(false);
    setView('login');
    postToParent({ type: 'RESIZE', state: 'button' });
  }, [setView, postToParent]);

  /** At load: this site's cache, or the Sign in button. */
  const restore = useCallback(
    async (isCancelled: () => boolean) => {
      const km = await restoreSharedSession();
      if (isCancelled()) return;
      if (km) await onSignedIn(km);
      else {
        setView('login');
        postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
      }
    },
    [onSignedIn, setView, postToParent]
  );

  /** Shows the sheet (the widget's Sign in, or the page's NostrBridge.login()). */
  const openSheet = useCallback(() => {
    setSheetOpen(true);
    postToParent({ type: 'RESIZE', state: 'modal' });
  }, [postToParent]);

  /** "Continue with Google": runs in the click, so the popup may open. */
  const google = useCallback(async () => {
    const signedIn = signInGlobally(parentOrigin);
    setSheetOpen(false);
    setView('connecting');
    postToParent({ type: 'RESIZE', state: 'button' });
    try {
      await onSignedIn(await signedIn);
    } catch (e) {
      showButton();
      const msg = (e as Error).message ?? '';
      if (msg === 'POPUP_BLOCKED') onError('Popup blocked', 'Allow popups for this signer and try again.', 'POPUP_BLOCKED');
      else if (!/closed|cancel/i.test(msg)) onError('Login failed', msg, 'LOGIN_FAILED');
    }
  }, [parentOrigin, onSignedIn, setView, postToParent, showButton, onError]);

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

  return { restore, openSheet, sheet };
}
