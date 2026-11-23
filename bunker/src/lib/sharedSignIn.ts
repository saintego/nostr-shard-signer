// The global account in the widget (#80, #81, #83). On shared-sign-in sites
// the widget never runs Web3Auth: it opens this site's cache with the device
// secret, or, on Sign in, the global sign-in popup. On sites with their own
// clientId the same happens after the site's own login, in that login's cache
// slot (siteCache.ts), with this site's marker (D7) kept and re-sent.

import type { Web3Auth } from '@web3auth/modal';
import type { BackupMethod } from './backup';
import { fetchSharedBlocklist } from './blocklist';
import {
  awaitGlobalResult,
  type GlobalAnswer,
  type GlobalOptions,
  openGlobalPopup,
} from './globalPopup';
import { keyMaterialFromSecret } from './identity';
import { MARKER_KIND } from './marker';
import { publishToSignerRelays } from './relayPublish';
import { isOriginBlocked } from './shared';
import { setLastLogin } from './siteAccount';
import {
  type CacheSlot,
  deleteSiteCache,
  loadSiteCache,
  SHARED_SLOT,
  type SiteCache,
  saveSiteCache,
} from './siteCache';
import { activeIdentity, withActive } from './siteGrant';
import { markUsedElsewhere } from './trustCheck';
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

/** Re-sends this site's stored marker (D7): no key needed, relays keep the newest. */
const resendMarker = (cache: SiteCache) => {
  try {
    if (cache.marker) void publishToSignerRelays([JSON.parse(cache.marker)]);
  } catch {
    // unreadable: dropped at the next global sign-in
  }
};

/**
 * This site's identity from the cache, or null (the user signs in). On an
 * own-clientId site, `siteSignedIn` says the site login was just confirmed:
 * the cache then opens whatever (B)'s window says, and the window restarts.
 */
export async function restoreSharedSession(
  slot: CacheSlot = SHARED_SLOT,
  siteSignedIn = false
): Promise<SharedSession | null> {
  const cache = await loadSiteCache(slot, { siteSignedIn }).catch(() => null);
  if (!cache) return null;
  if (slot.kind === 'shared') return session(cache);
  const renewed = siteSignedIn ? { ...cache, lastSiteSignIn: Date.now() } : cache;
  if (siteSignedIn) await saveSiteCache(renewed, slot);
  resendMarker(renewed);
  return session(renewed);
}

/** The marker the popup sent, if it's the kind and address this site expects. */
function checkedMarker(json: string | undefined, address: string | undefined): string | undefined {
  if (!json || !address) return undefined;
  try {
    const e = JSON.parse(json) as { kind?: unknown; tags?: unknown };
    const d = Array.isArray(e.tags)
      ? (e.tags as string[][]).find((t) => t[0] === 'd')?.[1]
      : undefined;
    return e.kind === MARKER_KIND && d === address ? json : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Sign in: opens the popup, which must happen synchronously in the click
 * (call this from the handler, before any await). Resolves with the session,
 * after keeping it in this site's cache. Also "Add or manage identities": the
 * popup's Welcome back hands over the new list.
 */
export function signInGlobally(
  site: string,
  options: GlobalOptions = {},
  slot: CacheSlot = SHARED_SLOT
): Promise<SharedSession> {
  const popup = openGlobalPopup();
  if (!popup) return Promise.reject(new Error('POPUP_BLOCKED'));
  return awaitGlobalResult(popup, site, options).then((answer) =>
    keepAnswer(answer, slot, options.markerAddress)
  );
}

/**
 * Keeps a global sign-in's answer (from the window, or from the widget itself,
 * #122) in this site's cache, and returns the session.
 */
export async function keepAnswer(
  { grant, backedUp, marker }: GlobalAnswer,
  slot: CacheSlot = SHARED_SLOT,
  markerAddress?: string
): Promise<SharedSession> {
  const now = Date.now();
  const checked = checkedMarker(marker, markerAddress);
  const cache: SiteCache =
    slot.kind === 'shared'
      ? { ...grant, createdAt: now }
      : {
          ...grant,
          createdAt: now,
          lastSiteSignIn: now,
          ...(checked ? { marker: checked } : {}),
        };
  await saveSiteCache(cache, slot);
  if (slot.kind === 'site') {
    setLastLogin(slot.loginHash);
    resendMarker(cache);
  }
  return backedUp ? { ...session(cache), backedUp } : session(cache);
}

/**
 * "Use this account on other sites" (D9): opens the popup (call from the
 * click) and sends it this site-only account's key, which becomes a stored
 * identity of the global account. Resolves when the popup says it's done; the
 * account is then marked "used elsewhere" here too (D13).
 */
export function bringOverGlobally(site: string, siteKeyHex: string, pubkey: string): Promise<void> {
  const popup = openGlobalPopup();
  if (!popup) return Promise.reject(new Error('POPUP_BLOCKED'));
  return awaitGlobalResult(popup, site, { intent: 'bring-over', siteKey: siteKeyHex }).then(
    () => markUsedElsewhere(pubkey),
    (e: unknown) => {
      if ((e as Error)?.message !== 'BROUGHT_OVER') throw e;
      markUsedElsewhere(pubkey);
    }
  );
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
export async function switchSharedIdentity(
  pubkey: string,
  slot: CacheSlot = SHARED_SLOT
): Promise<SharedSession | null> {
  const cache = await loadSiteCache(slot, { siteSignedIn: true }).catch(() => null);
  const next = cache ? withActive(cache, pubkey) : null;
  if (!cache || !next) return null;
  const updated: SiteCache = { ...cache, active: next.active };
  await saveSiteCache(updated, slot);
  return session(updated);
}

/**
 * Sign out on this site: Web3Auth's logout, then its keys deleted either way (a
 * session it can't log out, code 5113, would stay, #79), and on shared-sign-in
 * sites this site's cache. Other sites stay signed in.
 */
export async function signOutOnThisSite(
  w3a: Web3Auth | null,
  slot: CacheSlot | null
): Promise<void> {
  await endSession(w3a ? () => w3a.logout() : null, SITE_SESSION);
  if (!slot) return;
  deleteSiteCache(slot);
  if (slot.kind === 'site') setLastLogin(null);
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
