// Sign up and Sign in on sites with their own clientId (#73 D3, D5, D6; #83):
// the decision after the site's own login, rule (B), and the marker the
// global sign-in writes for the site (D7).
import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import type { Event } from 'nostr-tools';
import { finalizeEvent, generateSecretKey } from 'nostr-tools/pure';
import { deriveMarkerAddress, deriveRoot } from '../bunker/src/lib/derive.ts';
import { type AccountDeps, openGlobalAccount } from '../bunker/src/lib/globalAccount.ts';
import {
  buildList,
  type GlobalList,
  type IdentityRow,
  type PairingRow,
} from '../bunker/src/lib/globalListModel.ts';
import { buildMarker, MARKER_KIND } from '../bunker/src/lib/marker.ts';
import {
  type DeviceAnswer,
  decideAfterSiteLogin,
  type Hint,
  loginHash,
  parseGlobalLogin,
  remember,
  SITE_SIGN_IN_WINDOW_MS,
  type SiteState,
  withinWindow,
} from '../bunker/src/lib/siteAccount.ts';
import { opens, type SiteCache } from '../bunker/src/lib/siteCache.ts';

const vectors = JSON.parse(
  readFileSync(new URL('../bunker/src/lib/derive.vectors.json', import.meta.url), 'utf8')
);
const v = vectors.vectors[0];
const bytes = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));
const SITE = 'https://app.example';

const none: Hint = { found: false };
const note: Hint = { found: true, eventId: 'e'.repeat(64) };
const state = (o: Partial<SiteState> = {}): SiteState => ({
  intent: 'sign-in',
  globalLogin: 'offer',
  hasCache: false,
  answer: null,
  hint: none,
  ...o,
});
const answer = (o: Partial<DeviceAnswer> = {}): DeviceAnswer => ({
  notMine: [],
  confirmed: [],
  ...o,
});

test('D5: what follows the site login', () => {
  // This login's cache: the global account, no question.
  expect(decideAfterSiteLogin(state({ hasCache: true, hint: note }))).toEqual({ next: 'cache' });
  // Sign in, nothing found: the question; a note: the global sign-in verifies it.
  expect(decideAfterSiteLogin(state())).toEqual({ next: 'ask', question: 'reuse-or-site' });
  expect(decideAfterSiteLogin(state({ hint: note }))).toEqual({ next: 'global', noteFound: true });
  // Sign up: the choice (site-only first); a note: "a note was found".
  expect(decideAfterSiteLogin(state({ intent: 'sign-up' }))).toEqual({
    next: 'ask',
    question: 'sign-up-choice',
  });
  expect(decideAfterSiteLogin(state({ intent: 'sign-up', hint: note }))).toEqual({
    next: 'ask',
    question: 'note-found',
  });
  // Remembered answers.
  expect(decideAfterSiteLogin(state({ answer: answer({ kind: 'site' }) }))).toEqual({
    next: 'site-only',
  });
  expect(decideAfterSiteLogin(state({ answer: answer({ kind: 'global' }) }))).toEqual({
    next: 'global',
    noteFound: false,
  });
});

test('D5: a new note asks again once; "not mine" and a confirmation are remembered per note', () => {
  const site = answer({ kind: 'site' });
  expect(decideAfterSiteLogin(state({ answer: site, hint: note }))).toEqual({
    next: 'ask',
    question: 'note-again',
  });
  const confirmed = remember(site, { confirmed: note.found ? note.eventId : '' });
  expect(decideAfterSiteLogin(state({ answer: confirmed, hint: note }))).toEqual({
    next: 'site-only',
  });
  const notMine = remember(site, { notMine: note.found ? note.eventId : '' });
  expect(decideAfterSiteLogin(state({ answer: notMine, hint: note }))).toEqual({
    next: 'site-only',
  });
  // A newer note asks again.
  expect(
    decideAfterSiteLogin(
      state({ answer: confirmed, hint: { found: true, eventId: 'f'.repeat(64) } })
    ).next
  ).toBe('ask');
  // "Not mine" before any choice: Sign up goes on to the choice.
  const dismissed = remember(null, { notMine: note.found ? note.eventId : '' });
  expect(dismissed.kind).toBeUndefined();
  expect(decideAfterSiteLogin(state({ intent: 'sign-up', answer: dismissed, hint: note }))).toEqual(
    {
      next: 'ask',
      question: 'sign-up-choice',
    }
  );
});

test('D3: globalLogin off and require', () => {
  expect(parseGlobalLogin(null)).toBe('offer');
  expect(parseGlobalLogin('off')).toBe('off');
  expect(parseGlobalLogin('nonsense')).toBe('offer');
  expect(decideAfterSiteLogin(state({ globalLogin: 'off' }))).toEqual({ next: 'site-only' });
  expect(decideAfterSiteLogin(state({ globalLogin: 'off', intent: 'sign-up' }))).toEqual({
    next: 'site-only',
  });
  // On off sites a note still offers the global sign-in.
  expect(decideAfterSiteLogin(state({ globalLogin: 'off', hint: note })).next).toBe('global');
  expect(
    decideAfterSiteLogin(state({ globalLogin: 'require', answer: answer({ kind: 'site' }) })).next
  ).toBe('global');
});

test('rule (B): the device secret alone opens an own-clientId site cache for 7 days after the last site sign-in', () => {
  const now = 1_800_000_000_000;
  const cache = (lastSiteSignIn: number): SiteCache => ({
    storeKey: 'a'.repeat(64),
    identities: [{ secretKey: 'b'.repeat(64), pubkey: 'c'.repeat(64), label: null }],
    active: 'c'.repeat(64),
    createdAt: now - 90 * 24 * 3600 * 1000,
    lastSiteSignIn,
  });
  const slot = { kind: 'site' as const, loginHash: 'd'.repeat(32) };
  expect(opens(cache(now - 6 * 24 * 3600 * 1000), slot, now, false)).toBe(true);
  expect(opens(cache(now - 8 * 24 * 3600 * 1000), slot, now, false)).toBe(false);
  // With a site sign-in it opens whatever the window says; no 30-day global re-sign-in here.
  expect(opens(cache(now - 8 * 24 * 3600 * 1000), slot, now, true)).toBe(true);
  // Shared-sign-in sites keep their 30-day lifetime from the global sign-in.
  expect(opens(cache(now), { kind: 'shared' }, now, false)).toBe(false);
  expect(withinWindow(now - SITE_SIGN_IN_WINDOW_MS, now)).toBe(true);
  expect(withinWindow(now + 2 * 60_000, now)).toBe(false);
});

test('answers and caches are filed by a hash of the site login pubkey', async () => {
  const h = await loginHash('a'.repeat(64));
  expect(h).toMatch(/^[0-9a-f]{32}$/);
  expect(await loginHash('a'.repeat(64))).toBe(h);
  expect(await loginHash('b'.repeat(64))).not.toBe(h);
});

// ── The marker the global sign-in writes (D7) ────────────────────────────────

function fakeList(rows: IdentityRow[] = [], pairs: PairingRow[] = []): GlobalList {
  const st = { rows: [...rows], pairs: [...pairs] };
  return {
    synced: 'Synced',
    load: async () => buildList(st.rows, st.pairs),
    addDerived: async (index, pubkey, createdOn, label) => {
      st.rows.push({ pubkey, derivationIndex: index, label, createdOn, usedElsewhere: null });
    },
    pair: async (pubkey, origin) => {
      st.pairs.push({ origin, identityPubkey: pubkey });
    },
    unpair: async () => {},
    markUsedElsewhere: async () => {},
    close: async () => 'Synced',
  };
}

async function setup(markers: Event[]) {
  const address = await deriveMarkerAddress(generateSecretKey(), SITE);
  const published: Event[] = [];
  const deps: AccountDeps = {
    openList: async () =>
      fakeList([
        {
          pubkey: v.identities[0].pubkey,
          derivationIndex: 0,
          label: null,
          createdOn: SITE,
          usedElsewhere: null,
        },
      ]),
    query: async (filter) =>
      (filter as { '#d'?: string[] })['#d']
        ? markers.filter((m) => m.tags.some((t) => t[1] === address))
        : [],
    publish: async (events) => {
      published.push(...events);
    },
    now: () => 1_700_000_000,
    markerAddress: address,
  };
  return { address, published, deps };
}

test('D7: pairing an own-clientId site writes a marker; an existing one is handed back, not rewritten', async () => {
  const { published, deps } = await setup([]);
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, deps);
  expect(account.markerStatus).toBe('none');
  const json = await account.siteMarker();
  const marker = JSON.parse(json ?? '{}') as Event;
  expect(marker.kind).toBe(MARKER_KIND);
  expect(published.map((e) => e.id)).toEqual([marker.id]);
  expect(account.markerStatus).toBe('paired');
  // Asking again doesn't publish again.
  expect(await account.siteMarker()).toBe(json);
  expect(published).toHaveLength(1);
});

test('D7: re-pairing after "unpaired" writes a newer marker; leaving the site writes "unpaired"', async () => {
  const root = await deriveRoot(bytes(v.globalLoginKey));
  const address = await deriveMarkerAddress(generateSecretKey(), SITE);
  const old = await buildMarker(root, SITE, address, 'unpaired', 1_700_000_500);
  const { published, deps } = await setup([]);
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, {
    ...deps,
    markerAddress: address,
    query: async (f) => ((f as { '#d'?: string[] })['#d'] ? [old] : []),
  });
  expect(account.markerStatus).toBe('unpaired');
  const paired = JSON.parse((await account.siteMarker()) ?? '{}') as Event;
  expect(paired.created_at).toBeGreaterThan(old.created_at);
  await account.leaveSite();
  expect(account.markerStatus).toBe('unpaired');
  const last = published.at(-1);
  expect(last?.created_at).toBeGreaterThan(paired.created_at);
});

test('D7: a note from another key is reported as not yours', async () => {
  const { address, deps } = await setup([]);
  const forged = finalizeEvent(
    { kind: MARKER_KIND, created_at: 1, tags: [['d', address]], content: 'x' },
    generateSecretKey()
  );
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, {
    ...deps,
    query: async (f) => ((f as { '#d'?: string[] })['#d'] ? [forged] : []),
  });
  expect(account.markerStatus).toBe('not-yours');
});

test('shared-sign-in sites: no marker address, no marker', async () => {
  const { deps } = await setup([]);
  const { markerAddress: _, ...shared } = deps;
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, shared);
  expect(account.markerStatus).toBeNull();
  expect(await account.siteMarker()).toBeUndefined();
});
