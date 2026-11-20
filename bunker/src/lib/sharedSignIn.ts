// Shared-sign-in sites in the widget (#80, the shared-site part of #81): the
// widget never runs Web3Auth. It opens this site's cache with the device
// secret, or, on Sign in, the global sign-in popup, and keeps what the popup
// hands over in the cache.

import type { Web3Auth } from '@web3auth/modal';
import type { BackupMethod } from './backup';
import { fetchSharedBlocklist } from './blocklist';
import { awaitGlobalResult, type GlobalOptions, openGlobalPopup } from './globalPopup';
import { keyMaterialFromSecret } from './identity';
import { isOriginBlocked } from './shared';
import { deleteSiteCache, loadSiteCache, type SiteCache, saveSiteCache } from './siteCache';
import { activeIdentity, withActive } from './siteGrant';
import type { KeyMaterial } from './web3auth';
import { endSession, SITE_SESSION } from './web3authSession';

/** This site's signed-in state: the active identity and everything the cache holds. */
export interface SharedSession {
  readonly km: KeyMaterial;
  readonly cache: SiteCache;
  /** Set when the user saved a backup in the popup (#87). */
  readonly backedUp?: BackupMethod;
}

const session = (cache: SiteCache): SharedSession => ({
  km: keyMaterialFromSecret(activeIdentity(cache).secretKey),
  cache,
});

/** This site's identity from the cache, or null (the user signs in). */
export async function restoreSharedSession(): Promise<SharedSession | null> {
  const cache = await loadSiteCache().catch(() => null);
  return cache ? session(cache) : null;
}

/**
 * Sign in: opens the popup, which must happen synchronously in the click
 * (call this from the handler, before any await). Resolves with the session,
 * after keeping it in this site's cache. Also "Add or manage identities": the
 * popup's Welcome back hands over the new list.
 */
export function signInGlobally(site: string, options: GlobalOptions = {}): Promise<SharedSession> {
  const popup = openGlobalPopup();
  if (!popup) return Promise.reject(new Error('POPUP_BLOCKED'));
  return awaitGlobalResult(popup, site, options).then(async ({ grant, backedUp }) => {
    const cache = { ...grant, createdAt: Date.now() };
    await saveSiteCache(cache);
    return backedUp ? { ...session(cache), backedUp } : session(cache);
  });
}

/**
 * What a failed sign-in (or "Add or manage identities") means for the widget:
 * sign out here (every identity was unpaired), nothing (the user closed the
 * window), or an error to show.
 */
export function signInFailure(
  message: string
):
  | 'sign-out'
  | 'quiet'
  | { readonly title: string; readonly message: string; readonly code: string } {
  if (message === 'NO_IDENTITY') return 'sign-out';
  if (message === 'POPUP_BLOCKED')
    return {
      title: 'Popup blocked',
      message: 'Allow popups for this signer and try again.',
      code: 'POPUP_BLOCKED',
    };
  if (/closed|cancel/i.test(message)) return 'quiet';
  return { title: 'Login failed', message, code: 'LOGIN_FAILED' };
}

/** Switches this site to another of its identities (D14); null if it isn't one. */
export async function switchSharedIdentity(pubkey: string): Promise<SharedSession | null> {
  const cache = await loadSiteCache().catch(() => null);
  const next = cache ? withActive(cache, pubkey) : null;
  if (!cache || !next) return null;
  const updated = { ...next, createdAt: cache.createdAt };
  await saveSiteCache(updated);
  return session(updated);
}

/**
 * Sign out on this site: Web3Auth's logout, then its keys deleted either way (a
 * session it can't log out, code 5113, would stay, #79), and on shared-sign-in
 * sites this site's cache. Other sites stay signed in.
 */
export async function signOutOnThisSite(w3a: Web3Auth | null, shared: boolean): Promise<void> {
  await endSession(w3a ? () => w3a.logout() : null, SITE_SESSION);
  if (shared) deleteSiteCache();
}

/**
 * Shared mode: is this site on the operator's signed block list (#65)? On
 * failure, false: the built-in list still applies.
 */
export async function isBlockedBySignedList(
  site: string,
  rootPubkeyHex: string,
  relays: string[]
): Promise<boolean> {
  const list = await fetchSharedBlocklist(rootPubkeyHex, relays).catch(() => []);
  return isOriginBlocked(site, list);
}
