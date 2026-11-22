// Several sign-ins on one account (#73 D25, review 8; #98): envelopes,
// pointers, the version rule, what a login finds, and linking and unlinking.
import { expect, test } from '@playwright/test';
import type { Event, Filter } from 'nostr-tools';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { deriveIdentity, deriveRoot } from '../bunker/src/lib/derive.ts';
import {
  buildPointer,
  type EnvelopeBody,
  maskIdentifier,
  newer,
  openEnvelope,
  pointerAddress,
  readPointer,
  sealEnvelope,
} from '../bunker/src/lib/envelope.ts';
import type { EnvelopeCopies } from '../bunker/src/lib/envelopeStore.ts';
import { buildList, type GlobalList, type IdentityRow } from '../bunker/src/lib/globalListModel.ts';
import {
  type LinkingDeps,
  type Login,
  linkRefusal,
  lookUp,
  resolve,
  sealLink,
  storedPointers,
  unlinkRecord,
} from '../bunker/src/lib/linking.ts';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const primary = { provider: 'google', masked: 'a…@gmail.com' };

test('an envelope opens only with its login; tampering fails', async () => {
  const login = generateSecretKey();
  const body: EnvelopeBody = { v: 1, version: 1, scope: 'full', root: 'ab'.repeat(32), primary };
  const sealed = await sealEnvelope(login, body);
  expect(sealed.ct).not.toContain('abab');
  expect(await openEnvelope(login, sealed)).toEqual(body);
  expect(await openEnvelope(generateSecretKey(), sealed)).toBeNull();
  expect(await openEnvelope(login, { ...sealed, ct: `A${sealed.ct.slice(1)}` })).toBeNull();
});

test('the newest version wins; "unlinked" wins a tie', () => {
  const full: EnvelopeBody = { v: 1, version: 2, scope: 'full', root: 'ab'.repeat(32), primary };
  const unlinked: EnvelopeBody = { v: 1, version: 2, unlinked: true };
  expect(newer(full, unlinked)).toEqual(unlinked);
  expect(newer(unlinked, full)).toEqual(unlinked);
  expect(newer({ ...full, version: 3 }, unlinked)).toEqual({ ...full, version: 3 });
  expect(newer(null, full)).toEqual(full);
});

test('pointers: only the login\'s pointer key counts; the plain "unlinked" version too', async () => {
  const login = generateSecretKey();
  const addr = await pointerAddress(login);
  const { derivePointerKey } = await import('../bunker/src/lib/derive.ts');
  const pk = await derivePointerKey(login);
  const body: EnvelopeBody = { v: 1, version: 1, scope: 'full', root: 'cd'.repeat(32), primary };
  const linked = buildPointer(pk, addr.d, await sealEnvelope(login, body), 100);
  const forged = finalizeEvent(
    {
      kind: 30078,
      created_at: 200,
      tags: [['d', addr.d]],
      content: '{"v":1,"version":9,"unlinked":true}',
    },
    generateSecretKey()
  );
  expect(await readPointer([linked, forged], login)).toEqual(body);
  const unlinked = buildPointer(pk, addr.d, '{"v":1,"version":2,"unlinked":true}', 300);
  expect(await readPointer([linked, unlinked], login)).toEqual({
    v: 1,
    version: 2,
    unlinked: true,
  });
});

test('masking: enough to recognise, not to identify', () => {
  expect(maskIdentifier('alice@gmail.com')).toBe('a…@gmail.com');
  expect(maskIdentifier('@alice')).toBe('@a…');
  expect(maskIdentifier('alice')).toBe('a…');
});

// ── A small world: relays, Evolu databases by owner, global lists by root ──

function world() {
  const relay: Event[] = [];
  const copies = new Map<string, string[]>();
  const lists = new Map<string, { rows: IdentityRow[] }>();
  let answered = true;
  const deps: LinkingDeps = {
    query: async (f: Filter) => {
      if (!answered) return null;
      return relay.filter(
        (e) =>
          (!f.kinds || f.kinds.includes(e.kind)) &&
          (!f.authors || f.authors.includes(e.pubkey)) &&
          (!f['#d'] || e.tags.some((t) => t[0] === 'd' && f['#d']?.includes(t[1] ?? '')))
      );
    },
    publish: async (events) => {
      relay.push(...events);
    },
    openCopies: async (owner): Promise<EnvelopeCopies> => {
      const k = hex(owner);
      return {
        synced: answered,
        contents: async () => copies.get(k) ?? [],
        write: async (c) => {
          copies.set(k, [...(copies.get(k) ?? []), c]);
        },
        close: async () => {},
      };
    },
    openList: async (root): Promise<GlobalList> => {
      const st = lists.get(hex(root)) ?? { rows: [] };
      lists.set(hex(root), st);
      return {
        synced: answered ? 'Synced' : 'Offline',
        load: async () => buildList(st.rows, []),
        addDerived: async () => {},
        addStored: async () => {},
        pair: async () => {},
        unpair: async () => {},
        links: async () => [],
        saveLink: async () => {},
        markUsedElsewhere: async () => {},
        close: async () => 'Synced',
      };
    },
    now: () => 1_700_000_000,
  };
  const ownAccount = async (loginKey: Uint8Array) => {
    const root = await deriveRoot(loginKey);
    const id0 = await deriveIdentity(root, 0);
    lists.set(hex(root), {
      rows: [
        {
          pubkey: getPublicKey(id0),
          derivationIndex: 0,
          label: null,
          createdOn: null,
          usedElsewhere: null,
        },
      ],
    });
    return root;
  };
  return { deps, relay, ownAccount, offline: () => (answered = false) };
}

const login = (provider: string, masked: string): Login => ({
  key: generateSecretKey(),
  provider,
  userId: `${provider}:${masked}`,
  masked,
});

test('scenarios 51 and 52: Apple linked to a Google account opens the same root', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const apple = login('apple', 'a…@icloud.com');
  const root = await w.ownAccount(google.key);
  // Before linking, Apple finds nothing: "No account uses this sign-in yet".
  expect(resolve(await lookUp(apple.key, w.deps))).toEqual({ kind: 'none', wasUnlinked: false });
  expect(linkRefusal(google, apple, await lookUp(apple.key, w.deps))).toBeNull();
  const record = await sealLink(root, apple, { kind: 'full' }, primary, 1, w.deps);
  expect(record.scope).toBe('full');
  const r = resolve(await lookUp(apple.key, w.deps));
  expect(r.kind).toBe('linked');
  expect(r.kind === 'linked' && hex(r.root)).toBe(hex(root));
  expect(r.kind === 'linked' && r.primary).toEqual(primary);
  // Google is still its own account.
  expect(resolve(await lookUp(google.key, w.deps)).kind).toBe('own');
  // The stored pointer can be re-sent.
  expect(storedPointers([record])).toHaveLength(1);
});

test("scenarios 54 and 58: unlinking from the stored keys, without Apple's login", async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const apple = login('apple', 'a…@icloud.com');
  const root = await w.ownAccount(google.key);
  const record = await sealLink(root, apple, { kind: 'full' }, primary, 1, w.deps);
  const unlinked = await unlinkRecord(record, w.deps);
  expect(unlinked.version).toBe(2);
  expect(unlinked.unlinkedAt).not.toBeNull();
  expect(resolve(await lookUp(apple.key, w.deps))).toEqual({ kind: 'none', wasUnlinked: true });
  // Relinking: a newer version wins again.
  const relinked = await sealLink(root, apple, { kind: 'full' }, primary, 3, w.deps);
  expect(relinked.version).toBe(3);
  expect(resolve(await lookUp(apple.key, w.deps)).kind).toBe('linked');
});

test('scenario 63: a restricted link opens only its identities', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const facebook = login('facebook', 'a…');
  const root = await w.ownAccount(google.key);
  const id2 = await deriveIdentity(root, 2);
  const identities = [{ secretKey: hex(id2), pubkey: getPublicKey(id2), index: 2, label: 'Work' }];
  const record = await sealLink(
    root,
    facebook,
    { kind: 'restricted', identities },
    primary,
    1,
    w.deps
  );
  expect(record.scope).toEqual([getPublicKey(id2)]);
  const r = resolve(await lookUp(facebook.key, w.deps));
  expect(r.kind).toBe('restricted');
  if (r.kind !== 'restricted') return;
  expect(r.envelope.identities).toEqual(identities);
  expect(JSON.stringify(r.envelope)).not.toContain(hex(root));
});

test('scenarios 55, 61, 62 and item 8: what linking refuses, and asking which account', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const apple = login('apple', 'a…@icloud.com');
  const rootG = await w.ownAccount(google.key);
  await w.ownAccount(apple.key);
  // Apple has its own account: refused (55).
  expect(linkRefusal(google, apple, await lookUp(apple.key, w.deps))).toBe('own-account');
  // The same login twice (8).
  expect(linkRefusal(google, { ...google }, await lookUp(google.key, w.deps))).toBe('same-login');
  // A login linked to another account (62).
  const x = login('twitter', '@a…');
  await sealLink(rootG, x, { kind: 'full' }, primary, 1, w.deps);
  const other = login('google', 'b…@gmail.com');
  await w.ownAccount(other.key);
  expect(linkRefusal(other, x, await lookUp(x.key, w.deps))).toBe('linked-elsewhere');
  // A login with both its own account and an envelope: ask (61).
  await sealLink(rootG, apple, { kind: 'full' }, primary, 1, w.deps);
  expect(resolve(await lookUp(apple.key, w.deps)).kind).toBe('both');
});

test('scenario 59: relays not answering means "couldn\'t check", never "nothing found"', async () => {
  const w = world();
  const apple = login('apple', 'a…@icloud.com');
  w.offline();
  expect(resolve(await lookUp(apple.key, w.deps))).toEqual({ kind: 'unknown' });
  // A login whose own account is found still signs in.
  expect(resolve({ envelope: null, own: true, answered: false })).toEqual({ kind: 'own' });
});

test('the global list keeps the newest record per pointer; "unlinked" wins a tie', async () => {
  const { linkFromRow, newestLinks } = await import('../bunker/src/lib/globalListModel.ts');
  const row = (version: number, unlinkedAt: string | null) => ({
    provider: 'apple',
    masked: 'a…',
    scope: 'full',
    pointerPubkey: 'p',
    pointerKey: 'k',
    pointerD: 'd',
    envelopeOwner: 'o',
    version,
    pointerEvent: '{}',
    linkedAt: '2026-01-01T00:00:00.000Z',
    unlinkedAt,
  });
  const linked = linkFromRow(row(2, null));
  const unlinked = linkFromRow(row(2, '2026-02-01T00:00:00.000Z'));
  expect(newestLinks([linked, unlinked])[0]?.unlinkedAt).not.toBeNull();
  expect(newestLinks([linkFromRow(row(3, null)), unlinked])[0]?.version).toBe(3);
  expect(linkFromRow({ ...row(1, null), pointerPubkey: null })).toBeNull();
  expect(linkFromRow({ ...row(1, null), scope: '["a","b"]' })?.scope).toEqual(['a', 'b']);
});
