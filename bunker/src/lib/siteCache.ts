// The per-site cache on shared-sign-in sites (#73 D6, #81): what the global
// sign-in handed this site's iframe (the store key and the identity's key),
// sealed with the device secret, so the next visit needs no global sign-in.
// Sites with their own clientId add the site login to the seal (#81, waiting
// on C16). Sign out deletes it; it also expires after CACHE_LIFETIME_MS.

import { openWithDevice, sealWithDevice } from './deviceSecret';

/** Open question 1 of #73: 30 days until decided. */
export const CACHE_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

const STORAGE_KEY = 'nss_site_cache';

/** What the iframe keeps for this site. */
export interface SiteCache {
  /** Hex store key for this site (D2), for the site's Evolu store. */
  readonly storeKey: string;
  /** The identity used on this site: hex secret key and pubkey. */
  readonly identity: { readonly secretKey: string; readonly pubkey: string };
  /** When it was created (ms). */
  readonly createdAt: number;
}

const toB64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

const isHex64 = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);

/** A cache read back from storage, checked field by field. */
export function parseSiteCache(value: unknown): SiteCache | null {
  const v = value as Partial<SiteCache> | null;
  if (!v || !isHex64(v.storeKey) || !v.identity || typeof v.createdAt !== 'number') return null;
  if (!isHex64(v.identity.secretKey) || !isHex64(v.identity.pubkey)) return null;
  return { storeKey: v.storeKey, identity: { secretKey: v.identity.secretKey, pubkey: v.identity.pubkey }, createdAt: v.createdAt };
}

export const isExpired = (cache: SiteCache, now: number) => now - cache.createdAt > CACHE_LIFETIME_MS || cache.createdAt > now + 60_000;

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
