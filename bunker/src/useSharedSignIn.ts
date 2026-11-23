// The widget's side of the global account (#80, #83), as a hook so App.tsx
// doesn't grow (AGENTS.md, Files): restore this site's identity from its cache,
// the sign-in sheet, and the global popup opened from the user's click in it.
// On sites with their own clientId, useSiteAccount points it at the site
// login's cache slot and marker address (`target`).
import { createElement, useCallback, useRef, useState } from 'react';
import { IdentitySwitcher } from './components/IdentitySwitcher';
import { SharedSignInSheet } from './components/SharedSignInSheet';
import { recordBackup } from './lib/backup';
import { keyMaterialFromSecret } from './lib/identity';
import {
  restoreSharedSession,
  type SharedSession,
  signInFailure,
  signInGlobally,
  switchSharedIdentity,
} from './lib/sharedSignIn';
import { type CacheSlot, SHARED_SLOT } from './lib/siteCache';
import type { KeyMaterial } from './lib/web3auth';

/** Which cache the global account fills, and the site login's marker address (own clientId). */
export interface GlobalTarget {
  readonly slot: CacheSlot;
  readonly markerAddress?: string;
}

type View = 'login' | 'signing-in';
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
  /** Where the #37 backup marker is published. */
  publishRelays: string[];
  /** The user backed up their account in the popup (#87). */
  onBackedUp: () => void;
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
  publishRelays,
  onBackedUp,
}: Deps) {
  const [sheetOpen, setSheetOpen] = useState(false);
  const targetRef = useRef<GlobalTarget>({ slot: SHARED_SLOT });
  // What this site's cache holds: its identities and the active one (#84).
  const [session, setSession] = useState<SharedSession | null>(null);
  const signedIn = useCallback(
    async (s: SharedSession) => {
      setSession(s);
      await onSignedIn(s.km);
      if (!s.backedUp) return;
      // Every identity of this site counts as backed up (#37's marker, on every site).
      for (const i of s.cache.identities) {
        const key = keyMaterialFromSecret(i.secretKey).privateKeyBytes;
        void recordBackup(key, i.pubkey, s.backedUp, publishRelays).finally(() => key.fill(0));
      }
      onBackedUp();
    },
    [onSignedIn, publishRelays, onBackedUp]
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

  /** A failed sign-in, backup or manage; a failed manage keeps the current session. */
  const failed = useCallback(
    (e: unknown, managing: boolean) => {
      const failure = signInFailure((e as Error)?.message ?? '');
      if (failure === 'sign-out') return onSignOut();
      if (!managing) showButton();
      if (failure !== 'quiet') onError(failure.title, failure.message, failure.code);
    },
    [onSignOut, showButton, onError]
  );

  /**
   * "Continue with Google", and "Add or manage identities": runs in the click,
   * so the popup may open. A failed manage keeps the current session.
   */
  const google = useCallback(
    async (intent: 'sign-in' | 'backup' = 'sign-in') => {
      const { slot, markerAddress } = targetRef.current;
      const pending = signInGlobally(
        parentOrigin,
        {
          intent,
          ...(session ? { active: session.cache.active } : {}),
          ...(markerAddress ? { markerAddress } : {}),
        },
        slot
      );
      const managing = session !== null;
      setSheetOpen(false);
      if (!managing) {
        setView('signing-in');
        postToParent({ type: 'RESIZE', state: 'button' });
      }
      await pending.then(signedIn).catch((e: unknown) => failed(e, managing));
    },
    [parentOrigin, session, signedIn, setView, postToParent, failed]
  );

  /** Another identity of this site (D14): the page sees it through onAuthChange. */
  const switchTo = useCallback(
    async (pubkey: string) => {
      const next = await switchSharedIdentity(pubkey, targetRef.current.slot);
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

  /** "Back up now" (#37, #87): the popup opens at Backup; call from the click. */
  const backUp = useCallback(() => void google('backup'), [google]);

  /**
   * Own-clientId sites: opens a site login's cache (`siteSignedIn`: the login
   * was just confirmed; otherwise only within rule (B)'s window). True if it did.
   */
  const restoreIn = useCallback(
    async (target: GlobalTarget, siteSignedIn: boolean) => {
      const restored = await restoreSharedSession(target.slot, siteSignedIn);
      if (!restored) return false;
      targetRef.current = target;
      await signedIn(restored);
      return true;
    },
    [signedIn]
  );

  /** "Continue with your global account" on an own-clientId site; call from the click. */
  const continueGlobal = useCallback(
    (target: GlobalTarget) => {
      targetRef.current = target;
      return google('sign-in');
    },
    [google]
  );

  /** The cache this site's session uses, for Sign out (null: no global account here). */
  const currentSlot = useCallback(() => (session ? targetRef.current.slot : null), [session]);

  return {
    restore,
    openSheet,
    sheet,
    switcher,
    forget,
    backUp,
    restoreIn,
    continueGlobal,
    currentSlot,
  };
}
