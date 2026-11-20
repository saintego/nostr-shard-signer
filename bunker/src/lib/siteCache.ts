// The per-site cache on shared-sign-in sites (#73 D6, #81): what the global
// sign-in handed this site's iframe (the store key and the identities' keys),
// sealed with the device secret, so the next visit needs no global sign-in.
// Sites with their own clientId add the site login to the seal (#81, waiting
// on C16). Sign out deletes it; it also expires after CACHE_LIFETIME_MS.

import { openWithDevice, sealWithDevice } from './deviceSecret';
import { parseSiteGrant, type SiteGrant } from './siteGrant';

/** Open question 1 of #73: 30 days until decided. */
export const CACHE_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

const STORAGE_KEY = 'nss_site_cache';

/** What the iframe keeps for this site: the grant (#84: several identities) and its date. */
export interface SiteCache extends SiteGrant {
  /** When it was created (ms). */
  readonly createdAt: number;
}

const toB64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** A cache read back from storage, checked field by field. */
export function parseSiteCache(value: unknown): SiteCache | null {
  const grant = parseSiteGrant(value);
  const createdAt = (value as { createdAt?: unknown } | null)?.createdAt;
  return grant && typeof createdAt === 'number' ? { ...grant, createdAt } : null;
}

export const isExpired = (cache: SiteCache, now: number) =>
  now - cache.createdAt > CACHE_LIFETIME_MS || cache.createdAt > now + 60_000;

export async function saveSiteCache(cache: SiteCache): Promise<void> {
  const sealed = await sealWithDevice(new TextEncoder().encode(JSON.stringify(cache)));
  localStorage.setItem(STORAGE_KEY, toB64(sealed));
}

/** This site's cache, or null (none, not this device's, malformed, or expired; then it's deleted). */
export async function loadSiteCache(now = Date.now()): Promise<SiteCache | null> {
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
  if (!stored) return null;
  const plain = await openWithDevice(fromB64(stored));
  const cache = plain ? parseSiteCache(JSON.parse(new TextDecoder().decode(plain))) : null;
  if (!cache || isExpired(cache, now)) {
    deleteSiteCache();
    return null;
  }
  return cache;
}

/** Sign out on this site. */
export function deleteSiteCache(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // storage blocked: nothing was kept
  }
}
