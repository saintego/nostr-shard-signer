// The per-site cache (#73 D6, #81): what the global sign-in handed this site's
// iframe (the store key and the identities' keys), sealed with the device
// secret, so the next visit needs no global sign-in. Sign out deletes it.
//
// - Shared-sign-in sites: one cache per site; it expires CACHE_LIFETIME_MS
//   after the global sign-in that made it.
// - Sites with their own clientId: one cache per site login (keyed by a hash
//   of its pubkey, D5), so two people on one browser each have their own.
//   Rule (B), after C16: the device secret alone opens it for 7 days after the
//   last site sign-in; after that, a site sign-in opens it again. No 30-day
//   global re-sign-in there. It also keeps this site's signed marker (D7).

import { openWithDevice, sealWithDevice } from './deviceSecret';
import { withinWindow } from './siteAccount';
import { parseSiteGrant, type SiteGrant } from './siteGrant';

/** Shared-sign-in sites: 30 days (open question 1 of #73). */
export const CACHE_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

/** Which cache: the shared-sign-in site's, or one site login's (own clientId). */
export type CacheSlot =
  | { readonly kind: 'shared' }
  | { readonly kind: 'site'; readonly loginHash: string };

export const SHARED_SLOT: CacheSlot = { kind: 'shared' };

const storageKey = (slot: CacheSlot) =>
  slot.kind === 'shared' ? 'nss_site_cache' : `nss_site_cache:${slot.loginHash}`;

/** What the iframe keeps for this site: the grant (#84: several identities) and its dates. */
export interface SiteCache extends SiteGrant {
  /** When the global sign-in made it (ms). */
  readonly createdAt: number;
  /** Own-clientId sites: the last site sign-in (ms), for rule (B). */
  readonly lastSiteSignIn?: number;
  /** Own-clientId sites: this site's signed marker (JSON), re-sent at each sign-in (D7). */
  readonly marker?: string;
}

const toB64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** A cache read back from storage, checked field by field. */
export function parseSiteCache(value: unknown): SiteCache | null {
  const grant = parseSiteGrant(value);
  const v = value as { createdAt?: unknown; lastSiteSignIn?: unknown; marker?: unknown } | null;
  if (!grant || typeof v?.createdAt !== 'number') return null;
  return {
    ...grant,
    createdAt: v.createdAt,
    ...(typeof v.lastSiteSignIn === 'number' ? { lastSiteSignIn: v.lastSiteSignIn } : {}),
    ...(typeof v.marker === 'string' ? { marker: v.marker } : {}),
  };
}

/** Shared sites: past its lifetime (or dated in the future): deleted. */
export const isExpired = (cache: SiteCache, now: number) =>
  now - cache.createdAt > CACHE_LIFETIME_MS || cache.createdAt > now + 60_000;

/**
 * Whether the cache opens now. Shared sites: within its lifetime. Own-clientId
 * sites: with a site sign-in just made, or within (B)'s window without one.
 */
export function opens(
  cache: SiteCache,
  slot: CacheSlot,
  now: number,
  siteSignedIn: boolean
): boolean {
  if (slot.kind === 'shared') return !isExpired(cache, now);
  return siteSignedIn || withinWindow(cache.lastSiteSignIn ?? cache.createdAt, now);
}

export async function saveSiteCache(
  cache: SiteCache,
  slot: CacheSlot = SHARED_SLOT
): Promise<void> {
  const sealed = await sealWithDevice(new TextEncoder().encode(JSON.stringify(cache)));
  localStorage.setItem(storageKey(slot), toB64(sealed));
}

/**
 * The cache in `slot` if it opens now, else null. A shared site's expired or
 * unreadable cache is deleted; an own-clientId site's cache outside (B)'s
 * window is kept for the next site sign-in.
 */
export async function loadSiteCache(
  slot: CacheSlot = SHARED_SLOT,
  options: { readonly now?: number; readonly siteSignedIn?: boolean } = {}
): Promise<SiteCache | null> {
  const now = options.now ?? Date.now();
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(storageKey(slot));
  } catch {
    return null;
  }
  if (!stored) return null;
  const plain = await openWithDevice(fromB64(stored));
  const cache = plain ? parseSiteCache(JSON.parse(new TextDecoder().decode(plain))) : null;
  if (!cache || (slot.kind === 'shared' && isExpired(cache, now))) {
    deleteSiteCache(slot);
    return null;
  }
  return opens(cache, slot, now, options.siteSignedIn ?? false) ? cache : null;
}

/** Whether a cache is kept for `slot` (without opening it). */
export function hasSiteCache(slot: CacheSlot): boolean {
  try {
    return localStorage.getItem(storageKey(slot)) !== null;
  } catch {
    return false;
  }
}

/** Sign out on this site. */
export function deleteSiteCache(slot: CacheSlot = SHARED_SLOT): void {
  try {
    localStorage.removeItem(storageKey(slot));
  } catch {
    // storage blocked: nothing was kept
  }
}
