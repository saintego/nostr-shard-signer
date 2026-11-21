// Markers, the counter event and spaced publishing (#73 D7, D12; #82).
import { expect, test } from '@playwright/test';
import { type Event, finalizeEvent, generateSecretKey } from 'nostr-tools/pure';
import {
  buildCounter,
  findFreeIndex,
  highestNext,
  nextIndex,
  readCounter,
} from '../bunker/src/lib/counter.ts';
import { deriveMarkerAddress, deriveRoot } from '../bunker/src/lib/derive.ts';
import { buildMarker, MARKER_KIND, markerHint, readMarker } from '../bunker/src/lib/marker.ts';
import { published, publishSpaced } from '../bunker/src/lib/relayPublish.ts';

const SITE = 'https://example.com';
const NOW = 1_700_000_000;

/** A relay like the C13 ones: keeps the newest event per address, refuses an older copy. */
function mockRelay() {
  const byAddress = new Map<string, Event>();
  const addr = (e: Event) => `${e.kind}:${e.pubkey}:${e.tags.find((t) => t[0] === 'd')?.[1] ?? ''}`;
  return {
    publish(e: Event) {
      const have = byAddress.get(addr(e));
      if (have?.id === e.id) throw new Error('duplicate: already have this event');
      if (have && have.created_at >= e.created_at) throw new Error('blocked: have newer event');
      byAddress.set(addr(e), e);
    },
    query: (d: string) =>
      [...byAddress.values()].filter((e) => e.tags.some((t) => t[0] === 'd' && t[1] === d)),
  };
}

async function setup() {
  const root = await deriveRoot(generateSecretKey());
  const address = await deriveMarkerAddress(generateSecretKey(), SITE);
  return { root, address };
}

test('a marker is found by its address and read only with the root', async () => {
  const { root, address } = await setup();
  const marker = await buildMarker(root, SITE, address, 'paired', NOW);
  expect(marker.kind).toBe(MARKER_KIND);
  expect(marker.content).not.toContain('paired');
  expect(markerHint([marker], address)).toEqual({ found: true, eventId: marker.id });
  expect(markerHint([marker], 'f'.repeat(64))).toEqual({ found: false });
  expect((await readMarker([marker], root, SITE, address)).status).toBe('paired');
  // Another global account's root reads it as not its own.
  const otherRoot = await deriveRoot(generateSecretKey());
  expect((await readMarker([marker], otherRoot, SITE, address)).status).toBe('not-yours');
});

test("re-sending an old marker after unpairing can't undo it", async () => {
  const { root, address } = await setup();
  const relay = mockRelay();
  const paired = await buildMarker(root, SITE, address, 'paired', NOW);
  const unpaired = await buildMarker(root, SITE, address, 'unpaired', NOW + 60);
  relay.publish(paired);
  relay.publish(unpaired);
  expect(() => relay.publish(paired)).toThrow(/newer/);
  const reading = await readMarker(relay.query(address), root, SITE, address);
  expect(reading.status).toBe('unpaired');
  // Even if a relay hands back both versions, the newest wins.
  expect((await readMarker([paired, unpaired], root, SITE, address)).status).toBe('unpaired');
});

test('a forged marker is reported, not trusted', async () => {
  const { root, address } = await setup();
  const forger = generateSecretKey();
  const forged = finalizeEvent(
    { kind: MARKER_KIND, created_at: NOW, tags: [['d', address]], content: 'x' },
    forger
  );
  const reading = await readMarker([forged], root, SITE, address);
  expect(reading).toEqual({ status: 'not-yours', authors: [forged.pubkey] });
  // Without the root it's only a hint.
  expect(markerHint([forged], address).found).toBe(true);
  // A copy of a real marker with its content swapped fails the signature.
  const real = await buildMarker(root, SITE, address, 'paired', NOW);
  const tampered = {
    ...real,
    content: (await buildMarker(root, SITE, address, 'unpaired', NOW)).content,
  };
  expect((await readMarker([tampered], root, SITE, address)).status).toBe('not-yours');
  // A marker for another site (moved to this address) is unreadable here.
  const elsewhere = await buildMarker(root, 'https://other.example', address, 'paired', NOW);
  expect((await readMarker([elsewhere], root, SITE, address)).status).not.toBe('paired');
});

test('the counter event round-trips and only the counter key counts', async () => {
  const { root } = await setup();
  const old = await buildCounter(root, 2, NOW);
  const counter = await buildCounter(root, 5, NOW + 10);
  expect(counter.content).not.toContain('next');
  expect(await readCounter([old, counter], root)).toBe(5);
  const otherRoot = await deriveRoot(generateSecretKey());
  expect(await readCounter([counter], otherRoot)).toBeNull();
  expect(await readCounter([], root)).toBeNull();
});

test('the highest counter wins; look-ahead only when sources disagree', async () => {
  expect(highestNext({ relays: 3, evolu: 3, backup: 3 })).toEqual({ next: 3, agree: true });
  expect(highestNext({ relays: 2, evolu: 4, backup: null })).toEqual({ next: 4, agree: false });
  expect(highestNext({ relays: null, evolu: null, backup: null })).toEqual({
    next: 0,
    agree: false,
  });

  const queried: number[] = [];
  const used = new Set([4, 6]);
  const isUsed = async (i: number) => {
    queried.push(i);
    return used.has(i);
  };
  // Agreeing sources: no relay queries.
  expect(await nextIndex({ relays: 4, evolu: 4, backup: 4 }, isUsed)).toBe(4);
  expect(queried).toEqual([]);
  // 4 and 6 are used: skip past them, one npub per query.
  expect(await findFreeIndex(4, isUsed)).toBe(7);
  expect(queried).toEqual([4, 5, 6, 7, 8, 9]);
});

test('publishing: events to one relay are spaced out; rate limits retried; newer is fine', async () => {
  const { root, address } = await setup();
  const a = await buildMarker(root, SITE, address, 'paired', NOW);
  const b = await buildCounter(root, 1, NOW);
  const sleeps: number[] = [];
  const calls: Record<string, number> = {};
  const results = await publishSpaced(
    [a, b],
    ['wss://busy', 'wss://ok', 'wss://newer', 'wss://down'],
    {
      spacingMs: 100,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
      publishOne: async (relay, e) => {
        const key = `${relay}:${e.id}`;
        const n = (calls[key] ?? 0) + 1;
        calls[key] = n;
        if (relay === 'wss://busy' && n === 1)
          throw new Error('rate-limited: you are noting too much');
        if (relay === 'wss://newer') throw new Error('blocked: have newer event');
        if (relay === 'wss://down') throw new Error('WebSocket error');
      },
    }
  );
  const status = (r: string, id: string) =>
    results.find((x) => x.relay === r && x.eventId === id)?.status;
  expect(status('wss://busy', a.id)).toBe('ok');
  expect(calls[`wss://busy:${a.id}`]).toBe(2);
  expect(status('wss://newer', b.id)).toBe('newer');
  expect(status('wss://down', a.id)).toBe('failed');
  expect(sleeps).toContain(200); // backoff after the rate limit
  expect(sleeps.filter((ms) => ms === 100).length).toBe(4); // one pause per relay between a and b
  expect(published(results, a.id)).toBe(true);
  expect(published(results, 'none')).toBe(false);
});
