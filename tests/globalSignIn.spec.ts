// The global sign-in popup (#80): whom it serves, and what it hands a site.
import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import { getPublicKey } from 'nostr-tools/pure';
import { checkOpener } from '../bunker/src/lib/globalPopup.ts';
import { grantForSite, keyMaterialFromSecret } from '../bunker/src/lib/identity.ts';
import { isExpired, parseSiteCache, CACHE_LIFETIME_MS } from '../bunker/src/lib/siteCache.ts';

const vectors = JSON.parse(readFileSync(new URL('../bunker/src/lib/derive.vectors.json', import.meta.url), 'utf8'));
const bytes = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));

const SIGNER = '/nostr-shard-signer/signer.html';
const SITE = 'https://example.com';

/** A same-origin opener as the popup sees it. */
const opener = (o: { path?: string; framed?: boolean; ancestor?: string | null; crossOrigin?: boolean }) => {
  const self = {} as Window;
  const loc = {
    pathname: o.path ?? SIGNER,
    ancestorOrigins: o.ancestor === null ? undefined : { length: 1, 0: o.ancestor ?? SITE },
  };
  Object.defineProperty(self, 'location', {
    get: () => {
      if (o.crossOrigin) throw new Error('SecurityError');
      return loc;
    },
  });
  Object.defineProperty(self, 'top', { get: () => ((o.framed ?? true) ? ({} as Window) : self) });
  return self;
};

test.describe('checkOpener', () => {
  test("serves the signer's widget embedded in the site it asks for", () => {
    expect(checkOpener(opener({}), SITE, SIGNER)).toEqual({ ok: true });
    // Firefox has no ancestorOrigins: the site can't be cross-checked there.
    expect(checkOpener(opener({ ancestor: null }), SITE, SIGNER)).toEqual({ ok: true });
  });

  test('refuses other openers', () => {
    expect(checkOpener(null, SITE, SIGNER).ok).toBe(false);
    expect(checkOpener(opener({ crossOrigin: true }), SITE, SIGNER).reason).toBe('opener on another origin');
    // Another page on the signer's origin (before #60: the portal, examples, other projects).
    expect(checkOpener(opener({ path: '/nostr-shard-signer/examples/evolustr.html' }), SITE, SIGNER).reason).toBe(
      'opener is not the signer'
    );
    // The signer page opened top-level, not as a widget on a site.
    expect(checkOpener(opener({ framed: false }), SITE, SIGNER).reason).toBe('opener is not embedded in a site');
    // A widget on another site asking for this one.
    expect(checkOpener(opener({ ancestor: 'https://evil.example' }), SITE, SIGNER).reason).toBe(
      'the site does not match the widget'
    );
    expect(checkOpener(opener({ ancestor: null }), 'https://example.com/path', SIGNER).reason).toBe('not an origin');
  });
});

test('grantForSite: identity 0 and the site store key from the frozen vectors; the login key is wiped', async () => {
  const v = vectors.vectors[0];
  const site = v.sites[0];
  const login = bytes(v.globalLoginKey);
  const grant = await grantForSite(login, site.canonical);
  expect(grant.identity.pubkey).toBe(v.identities[0].pubkey);
  expect(grant.identity.secretKey).toBe(v.identities[0].secret);
  expect(grant.storeKey).toBe(site.storeKey);
  expect(login.every((b) => b === 0)).toBe(true);
  expect(getPublicKey(keyMaterialFromSecret(grant.identity.secretKey).privateKeyBytes)).toBe(grant.identity.pubkey);
});

test('site cache: only well-formed caches are used, and they expire', () => {
  const ok = { storeKey: 'a'.repeat(64), identity: { secretKey: 'b'.repeat(64), pubkey: 'c'.repeat(64) }, createdAt: 1000 };
  expect(parseSiteCache(ok)).toEqual(ok);
  expect(parseSiteCache({ ...ok, storeKey: 'zz' })).toBeNull();
  expect(parseSiteCache({ ...ok, identity: { secretKey: 'b'.repeat(64) } })).toBeNull();
  expect(parseSiteCache(null)).toBeNull();
  expect(isExpired(ok, 1000 + CACHE_LIFETIME_MS)).toBe(false);
  expect(isExpired(ok, 1001 + CACHE_LIFETIME_MS)).toBe(true);
  // A cache dated in the future isn't trusted.
  expect(isExpired({ ...ok, createdAt: 10_000_000 }, 1000)).toBe(true);
});
