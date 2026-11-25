// The global account in the sign-in popup (#73 D8, D12, D14, D15; #84):
// Welcome back, pairing, creating and unpairing, and what a site is handed.
import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import type { Event } from 'nostr-tools';
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import { buildCounter, readCounter } from '../bunker/src/lib/counter.ts';
import { processRpc } from '../bunker/src/lib/crypto.ts';
import { deriveRoot } from '../bunker/src/lib/derive.ts';
import { type AccountDeps, openGlobalAccount } from '../bunker/src/lib/globalAccount.ts';
import {
  buildList,
  type GlobalList,
  type IdentityRow,
  listNext,
  type PairingRow,
  pairedWith,
} from '../bunker/src/lib/globalListModel.ts';
import { accountNext } from '../bunker/src/lib/popupFlow.ts';
import { parseSiteGrant, withActive } from '../bunker/src/lib/siteGrant.ts';

const vectors = JSON.parse(
  readFileSync(new URL('../bunker/src/lib/derive.vectors.json', import.meta.url), 'utf8')
);
const v = vectors.vectors[0];
const bytes = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));
const id = (i: number) => v.identities.find((x: { index: number }) => x.index === i);
const SITE = 'https://example.com';
const OTHER = 'https://other.example';

/** The global list in memory, like Evolu's rows. */
function fakeList(
  identities: IdentityRow[] = [],
  pairings: PairingRow[] = [],
  synced: GlobalList['synced'] = 'Synced'
) {
  const state = { identities: [...identities], pairings: [...pairings], closed: false };
  const list: GlobalList = {
    synced,
    load: async () => buildList(state.identities, state.pairings),
    addDerived: async (index, pubkey, createdOn, label) => {
      state.identities.push({
        pubkey,
        derivationIndex: index,
        label,
        createdOn,
        usedElsewhere: null,
      });
    },
    pair: async (pubkey, origin) => {
      state.pairings.push({ origin, identityPubkey: pubkey });
    },
    unpair: async (pubkey, origin) => {
      state.pairings = state.pairings.filter(
        (p) => !(p.origin === origin && p.identityPubkey === pubkey)
      );
    },
    addStored: async () => {},
    links: async () => [],
    saveLink: async () => {},
    markUsedElsewhere: async (pubkey) => {
      state.identities = state.identities.map((r) =>
        r.pubkey === pubkey ? { ...r, usedElsewhere: 'x' } : r
      );
    },
    close: async () => {
      state.closed = true;
      return synced;
    },
  };
  return { list, state };
}

function deps(list: GlobalList, relayEvents: Event[] | null = []) {
  const published: Event[] = [];
  const queries: unknown[] = [];
  const d: AccountDeps = {
    openList: async () => list,
    query: async (filter) => {
      queries.push(filter);
      if (relayEvents === null) return null;
      return relayEvents.filter((e) => !filter.authors || filter.authors.includes(e.pubkey));
    },
    publish: async (events) => {
      published.push(...events);
    },
    now: () => 1_700_000_000,
  };
  return { d, published, queries };
}

const row = (
  i: number,
  createdOn: string | null = OTHER,
  label: string | null = null
): IdentityRow => ({
  pubkey: id(i).pubkey,
  derivationIndex: i,
  label,
  createdOn,
  usedElsewhere: null,
});

test('a first sign-in: identity 0, paired, no Welcome back; the login key is wiped', async () => {
  const { list, state } = fakeList([], [], 'NoRelays');
  const { d } = deps(list);
  const login = bytes(v.globalLoginKey);
  const account = await openGlobalAccount(login, SITE, d);
  expect(login.every((b) => b === 0)).toBe(true);
  expect(account.isNew).toBe(true);
  expect(account.list.map((i) => i.pubkey)).toEqual([id(0).pubkey]);
  await account.pair(id(0).pubkey);
  const grant = await account.grant(id(0).pubkey);
  expect(grant.identities).toEqual([
    { secretKey: id(0).secret, pubkey: id(0).pubkey, label: null },
  ]);
  expect(grant.storeKey).toBe(v.sites[0].storeKey);
  expect(state.pairings).toEqual([{ origin: SITE, identityPubkey: id(0).pubkey }]);
  await account.close();
  expect(state.closed).toBe(true);
});

test("a new account's identity 0 gets the sign-in account's name and picture when kept (D15)", async () => {
  const { list } = fakeList([], [], 'NoRelays');
  const { d, published } = deps(list);
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, d);
  const first = account.list[0];
  if (!first) throw new Error('no identity 0');
  await account.pair(first.pubkey);
  await account.publishProfile(first.pubkey, { name: 'Alice', picture: 'https://p.example/a.png' });
  const profile = published.find((e) => e.kind === 0);
  expect(profile?.pubkey).toBe(first.pubkey);
  expect(JSON.parse(profile?.content ?? '{}')).toEqual({
    name: 'Alice',
    picture: 'https://p.example/a.png',
  });
  await expect(account.publishProfile('ab'.repeat(32), { name: 'x' })).rejects.toThrow();
});

test('Welcome back lists the identities; an existing account never gets a second identity 0 (scenario 10)', async () => {
  const { list } = fakeList([row(0), row(1)], [{ origin: OTHER, identityPubkey: id(0).pubkey }]);
  const { d } = deps(list);
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, d);
  expect(account.isNew).toBe(false);
  expect(account.list.map((i) => i.index)).toEqual([0, 1]);
  expect(account.paired).toEqual([]);
  await account.pair(id(1).pubkey);
  expect(account.paired.map((i) => i.pubkey)).toEqual([id(1).pubkey]);
  expect((await account.grant(id(1).pubkey)).active).toBe(id(1).pubkey);
  // Only identities paired with this site are handed over.
  await expect(account.grant(id(0).pubkey)).rejects.toThrow(/not paired/);
});

test('an unsynced device still lists identity 0 and says the list may be incomplete', async () => {
  const { list } = fakeList([], [], 'Offline');
  const root = await deriveRoot(bytes(v.globalLoginKey));
  const counter = await buildCounter(root, 3, 1_699_999_000);
  const { d } = deps(list, [counter]);
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, d);
  expect(account.complete).toBe(false);
  expect(account.isNew).toBe(false); // the counter says identities exist
  expect(account.list[0]?.pubkey).toBe(id(0).pubkey);
});

test('creating: the next index from the counter, paired, counter published; Google profile only if asked (D12, D15)', async () => {
  const root = await deriveRoot(bytes(v.globalLoginKey));
  const counter = await buildCounter(root, 2, 1_699_999_000);
  const { list } = fakeList([row(0), row(1)], [{ origin: SITE, identityPubkey: id(0).pubkey }]);
  const { d, published } = deps(list, [counter]);
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, d);
  const created = await account.create('Work');
  expect(created.index).toBe(2);
  expect(created.pubkey).toBe(id(2).pubkey);
  expect(created.label).toBe('Work');
  expect(account.paired.map((i) => i.index)).toEqual([0, 2]);
  expect(published.map((e) => e.kind)).toEqual([30078]); // the counter, no profile
  const withProfile = await account.create(null, {
    name: 'Ann',
    picture: 'https://example.com/a.png',
  });
  expect(withProfile.index).toBe(3);
  const profile = published.find((e) => e.kind === 0);
  expect(profile?.pubkey).toBe(
    getPublicKey(
      bytes(
        (await account.grant(withProfile.pubkey)).identities.find(
          (i) => i.pubkey === withProfile.pubkey
        )?.secretKey ?? ''
      )
    )
  );
  expect(JSON.parse(profile?.content ?? '{}')).toEqual({
    name: 'Ann',
    picture: 'https://example.com/a.png',
  });
});

test('sources disagree: look-ahead skips identities used on relays; one npub per query', async () => {
  const { list } = fakeList([row(0)], []);
  // Identity 1 published something on another device that didn't sync.
  const used = {
    id: 'x',
    pubkey: id(1).pubkey,
    kind: 1,
    created_at: 1,
    tags: [],
    content: '',
    sig: '',
  } as Event;
  const { d, queries } = deps(list, [used]);
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, d);
  const created = await account.create(null);
  expect(created.index).toBe(2);
  const authorQueries = queries.filter((q) => (q as { kinds?: number[] }).kinds === undefined) as {
    authors: string[];
  }[];
  expect(authorQueries.every((q) => q.authors.length === 1)).toBe(true);
});

test('no counter is published when the relays did not answer', async () => {
  const { list } = fakeList([row(0), row(1)], []);
  const { d, published } = deps(list, null);
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, d);
  const created = await account.create(null);
  expect(created.index).toBe(2);
  expect(published).toEqual([]);
});

test('unpairing removes an identity from this site only (scenario 11, shared sites)', async () => {
  const { list } = fakeList(
    [row(0), row(1)],
    [
      { origin: SITE, identityPubkey: id(0).pubkey },
      { origin: SITE, identityPubkey: id(1).pubkey },
      { origin: OTHER, identityPubkey: id(0).pubkey },
    ]
  );
  const { d } = deps(list);
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, d);
  await account.unpair(id(0).pubkey);
  expect(account.paired.map((i) => i.pubkey)).toEqual([id(1).pubkey]);
  expect(account.list.find((i) => i.index === 0)?.sites).toEqual([OTHER]);
  const grant = await account.grant(id(1).pubkey);
  expect(grant.identities.map((i) => i.pubkey)).toEqual([id(1).pubkey]);
});

test('the global list: one entry per pubkey, derived by index, and the counter it implies', () => {
  const list = buildList(
    [
      row(1, SITE, 'B'),
      row(0),
      row(1, OTHER, null),
      {
        pubkey: 'f'.repeat(64),
        derivationIndex: null,
        label: 'imported',
        createdOn: null,
        usedElsewhere: '2026-01-01T00:00:00.000Z',
      },
    ],
    [
      { origin: SITE, identityPubkey: id(1).pubkey },
      { origin: SITE, identityPubkey: 'unknown' },
    ]
  );
  expect(list.map((i) => i.index)).toEqual([0, 1, null]);
  expect(list[1]?.label).toBe('B');
  expect(list[2]?.usedElsewhere).toBe(true);
  expect(pairedWith(list, 'https://EXAMPLE.com/x').map((i) => i.index)).toEqual([1]);
  expect(listNext(list)).toBe(2);
  expect(listNext([])).toBeNull();
});

test('a grant is checked field by field; switching only to one of its identities', () => {
  const a = { secretKey: 'a'.repeat(64), pubkey: 'b'.repeat(64), label: null };
  const b = { secretKey: 'c'.repeat(64), pubkey: 'd'.repeat(64), label: 'Work' };
  const ok = { storeKey: 'e'.repeat(64), identities: [a, b], active: a.pubkey };
  expect(parseSiteGrant(ok)).toEqual(ok);
  expect(parseSiteGrant({ ...ok, active: 'f'.repeat(64) })).toBeNull();
  expect(parseSiteGrant({ ...ok, identities: [a, a] })).toBeNull();
  expect(parseSiteGrant({ ...ok, identities: [] })).toBeNull();
  expect(parseSiteGrant({ ...ok, identities: [{ ...a, secretKey: 'zz' }] })).toBeNull();
  expect(withActive(ok, b.pubkey)?.active).toBe(b.pubkey);
  expect(withActive(ok, 'f'.repeat(64))).toBeNull();
});

test('D14: sign_event for another identity is refused; an empty pubkey is fine', async () => {
  const key = bytes(id(0).secret);
  const evt = (pubkey?: string) =>
    JSON.stringify({
      kind: 1,
      created_at: 1,
      tags: [],
      content: 'hi',
      ...(pubkey === undefined ? {} : { pubkey }),
    });
  await expect(processRpc('sign_event', [evt(id(1).pubkey)], key, id(0).pubkey)).rejects.toThrow(
    /another identity/
  );
  expect(JSON.parse(await processRpc('sign_event', [evt('')], key, id(0).pubkey)).pubkey).toBe(
    id(0).pubkey
  );
  expect(
    JSON.parse(await processRpc('sign_event', [evt(id(0).pubkey)], key, id(0).pubkey)).pubkey
  ).toBe(id(0).pubkey);
});

test('#136: new only on evidence: unsynced, unanswered or already found means an existing account', async () => {
  const login = () => bytes(v.globalLoginKey);
  // Evolu didn't sync: the list may just be missing.
  let a = await openGlobalAccount(login(), SITE, deps(fakeList([], [], 'Offline').list).d);
  expect(a.isNew).toBe(false);
  expect(a.listMissing).toBe(true);
  // The relays didn't answer the counter query.
  a = await openGlobalAccount(login(), SITE, deps(fakeList([], [], 'Synced').list, null).d);
  expect(a.isNew).toBe(false);
  // The lookup found the account (events by identity 0, a counter, a list).
  a = await openGlobalAccount(login(), SITE, {
    ...deps(fakeList([], [], 'Synced').list).d,
    knownExisting: true,
  });
  expect(a.isNew).toBe(false);
  expect(a.listMissing).toBe(true);
  // Everything answered, nothing anywhere: new.
  a = await openGlobalAccount(login(), SITE, deps(fakeList([], [], 'Synced').list).d);
  expect(a.isNew).toBe(true);
  expect(a.listMissing).toBe(false);
});

test('#136: a profile is never published over an existing one, nor when relays are silent', async () => {
  const existing = finalizeEvent(
    {
      kind: 0,
      created_at: 1,
      tags: [],
      content: JSON.stringify({ about: 'mine', lud16: 'a@b.c' }),
    },
    bytes(id(0).secret)
  );
  const withProfile = deps(fakeList([], [], 'Synced').list, [existing]);
  let a = await openGlobalAccount(bytes(v.globalLoginKey), SITE, withProfile.d);
  expect(await a.profileFree(id(0).pubkey)).toBe(false);
  expect(await a.publishProfile(id(0).pubkey, { name: 'Alice' })).toBe(false);
  expect(withProfile.published.filter((e) => e.kind === 0)).toEqual([]);
  const silent = deps(fakeList([], [], 'Synced').list, null);
  a = await openGlobalAccount(bytes(v.globalLoginKey), SITE, silent.d);
  expect(await a.publishProfile(id(0).pubkey, { name: 'Alice' })).toBe(false);
  expect(silent.published.filter((e) => e.kind === 0)).toEqual([]);
});

test('#136: a missing counter is written from the synced list', async () => {
  const { list } = fakeList([row(0), row(1)], [], 'Synced');
  const { d, published } = deps(list, []);
  await openGlobalAccount(bytes(v.globalLoginKey), SITE, d);
  await expect.poll(() => published.length).toBe(1);
  const root = await deriveRoot(bytes(v.globalLoginKey));
  expect(await readCounter(published, root)).toBe(2);
});

test('#136: "Create a new account" after a full lookup is new, without checking again', async () => {
  // Evolu slow and relays silent the second time: the lookup already proved it.
  const { d, queries } = deps(fakeList([], [], 'Offline').list, null);
  const a = await openGlobalAccount(bytes(v.globalLoginKey), SITE, { ...d, provenNew: true });
  expect(a.isNew).toBe(true);
  expect(a.listMissing).toBe(false);
  const before = queries.length;
  expect(await a.profileFree(id(0).pubkey)).toBe(true);
  expect(queries.length).toBe(before); // no extra profile lookup
});

test('#136: a missing list of an account that only had identity 0 needs no question', async () => {
  const root = await deriveRoot(bytes(v.globalLoginKey));
  const open = async (counterNext: number | null, relaysAnswer = true) => {
    const events =
      counterNext === null ? [] : [await buildCounter(root, counterNext, 1_699_999_000)];
    const { d } = deps(fakeList([], [], 'Synced').list, relaysAnswer ? events : null);
    return openGlobalAccount(bytes(v.globalLoginKey), SITE, { ...d, knownExisting: true });
  };
  const only0 = await open(1);
  expect(only0.onlyIdentity0).toBe(true);
  expect(accountNext(only0, {})).toEqual({ kind: 'pair', pubkey: id(0).pubkey });
  // Asked for on purpose: still shown.
  expect(accountNext(only0, { intent: 'manage' })).toEqual({ kind: 'show' });
  // Several identities, or relays that can't say: the user picks.
  expect((await open(3)).onlyIdentity0).toBe(false);
  expect(accountNext(await open(3), {})).toEqual({ kind: 'show' });
  expect((await open(null, false)).onlyIdentity0).toBe(false);
});

test('#140: the counter never goes down: read from every relay before writing, the highest wins', async () => {
  const root = await deriveRoot(bytes(v.globalLoginKey));
  const fast = await buildCounter(root, 3, 1_699_999_100); // newer, lower: published after a partial read
  const slow = await buildCounter(root, 7, 1_699_999_000);
  expect(await readCounter([fast, slow], root)).toBe(7);
  const { list } = fakeList([row(0)], [{ origin: SITE, identityPubkey: id(0).pubkey }], 'Synced');
  const { d, published } = deps(list, [fast]); // the quorum read sees only the fast relays
  const account = await openGlobalAccount(bytes(v.globalLoginKey), SITE, {
    ...d,
    queryAll: async () => [fast, slow],
  });
  const created = await account.create(null);
  expect(created.index).toBeGreaterThanOrEqual(7);
  const counters = published.filter((e) =>
    e.tags.some((t) => t[1] === 'nostr-shard-signer/counter')
  );
  expect(await readCounter(counters, root)).toBeGreaterThanOrEqual(8);
  // Relays that can't say: no counter is written.
  const silent = deps(fakeList([row(0)], [], 'Synced').list, [fast]);
  const b = await openGlobalAccount(bytes(v.globalLoginKey), SITE, {
    ...silent.d,
    queryAll: async () => null,
  });
  await b.create(null);
  expect(
    silent.published.filter((e) => e.tags.some((t) => t[1] === 'nostr-shard-signer/counter'))
  ).toEqual([]);
});
