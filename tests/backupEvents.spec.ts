// Signed copies of the account's events in the backup file, and "Publish
// again" (#146).
import { expect, test } from '@playwright/test';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import {
  collectBackupEvents,
  eventsToPublish,
  newestPerAddress,
} from '../bunker/src/lib/backupEvents.ts';
import {
  buildBackupFile,
  openBackupFile,
  parseBackupFile,
  withRoot,
} from '../bunker/src/lib/backupFile.ts';

const sk = generateSecretKey();
const me = getPublicKey(sk);
const ev = (kind: number, created_at: number, tags: string[][] = [], content = '') =>
  finalizeEvent({ kind, created_at, tags, content }, sk);
const VAULT_D = 'evolustr:signer:abc';

test('keeps the newest per address, valid signatures only', () => {
  const old = ev(0, 1, [], '{"name":"old"}');
  const recent = ev(0, 2, [], '{"name":"new"}');
  const forged = { ...ev(3, 5), sig: '00'.repeat(64) };
  expect(newestPerAddress([old, recent, forged]).map((e) => e.content)).toEqual(['{"name":"new"}']);
});

test('collects vaults, the counter, profiles and pointers; no other app data', async () => {
  const vault = ev(30078, 10, [['d', VAULT_D]], 'sealed');
  const otherApp = ev(30078, 10, [['d', 'some-app/settings']], 'x');
  const profile = ev(0, 10, [], '{"name":"me"}');
  const follows = ev(3, 10, [['p', 'a'.repeat(64)]]);
  const counter = ev(30078, 10, [['d', 'nostr-shard-signer/counter']], 'enc');
  const pointer = ev(30078, 10, [['d', 'pointer-d']], 'sealed envelope');
  const all = [vault, otherApp, profile, follows, counter];
  const kept = await collectBackupEvents(me, [me], [JSON.stringify(pointer), ''], async (f) =>
    all.filter(
      (e) =>
        (!f.kinds || f.kinds.includes(e.kind)) &&
        (!f.authors || f.authors.includes(e.pubkey)) &&
        (!f['#d'] || e.tags.some((t) => t[0] === 'd' && f['#d']?.includes(t[1] ?? '')))
    )
  );
  const ids = kept.events.map((e) => e.id).sort();
  expect(ids).toEqual([vault.id, profile.id, follows.id, counter.id].sort());
  expect(kept.pointers.map((e) => e.id)).toEqual([pointer.id]);
});

test('old link pointers are sent only when the user asks', () => {
  const kept = { events: [ev(0, 1)], pointers: [ev(30078, 1, [['d', 'p']])] };
  const now = Date.parse('2026-12-31T00:00:00Z');
  expect(eventsToPublish(kept, '2026-12-20T00:00:00Z', now, false)).toHaveLength(2); // 11 days
  expect(eventsToPublish(kept, '2026-10-01T00:00:00Z', now, false)).toHaveLength(1); // 91 days
  expect(eventsToPublish(kept, '2026-10-01T00:00:00Z', now, true)).toHaveLength(2);
});

test('the backup file carries the events through encryption', async () => {
  const root = generateSecretKey();
  const events = { events: [ev(0, 1, [], '{"name":"me"}')], pointers: [] };
  const text = await buildBackupFile({
    v: 1,
    root: Buffer.from(root).toString('hex'),
    counter: 1,
    identities: [],
    createdAt: '2026-11-28T00:00:00.000Z',
    events,
  });
  expect(text).not.toContain('"name"'); // encrypted
  const file = parseBackupFile(text);
  if (!file.ok) throw new Error(file.error);
  const body = await openBackupFile(file.value, withRoot(root));
  if (!body.ok) throw new Error(body.error);
  expect(body.value.events?.events[0]?.id).toBe(events.events[0]?.id);
});
