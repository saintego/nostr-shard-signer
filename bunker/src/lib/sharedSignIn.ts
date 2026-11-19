// Shared-sign-in sites in the widget (#80, the shared-site part of #81): the
// widget never runs Web3Auth. It opens this site's cache with the device
// secret, or, on Sign in, the global sign-in popup, and keeps what the popup
// hands over in the cache.

import { fetchSharedBlocklist } from './blocklist';
import { awaitGlobalResult, openGlobalPopup } from './globalPopup';
import { keyMaterialFromSecret } from './identity';
import { isOriginBlocked } from './shared';
import { deleteSiteCache, loadSiteCache, saveSiteCache } from './siteCache';
import type { Web3Auth } from '@web3auth/modal';
import type { KeyMaterial } from './web3auth';
import { endSession, SITE_SESSION } from './web3authSession';

/** This site's identity from the cache, or null (the user signs in). */
export async function restoreSharedSession(): Promise<KeyMaterial | null> {
  const cache = await loadSiteCache().catch(() => null);
  return cache ? keyMaterialFromSecret(cache.identity.secretKey) : null;
}

/**
 * Sign in: opens the popup, which must happen synchronously in the click
 * (call this from the handler, before any await). Resolves with the identity,
 * after keeping it in this site's cache.
 */
export function signInGlobally(site: string): Promise<KeyMaterial> {
  const popup = openGlobalPopup();
  if (!popup) return Promise.reject(new Error('POPUP_BLOCKED'));
  return awaitGlobalResult(popup, site).then(async (grant) => {
    await saveSiteCache({ ...grant, createdAt: Date.now() });
    return keyMaterialFromSecret(grant.identity.secretKey);
  });
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
export async function isBlockedBySignedList(site: string, rootPubkeyHex: string, relays: string[]): Promise<boolean> {
  const list = await fetchSharedBlocklist(rootPubkeyHex, relays).catch(() => []);
  return isOriginBlocked(site, list);
}
