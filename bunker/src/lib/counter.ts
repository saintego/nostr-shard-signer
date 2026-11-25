// The identity counter (#73 D12, #82): the next unused derivation index.
// Kept in three places: one counter event on Nostr (published by the
// root-derived counter key, content NIP-44 encrypted to the root), the global
// Evolu list and the backup. The signer takes the highest. Only when they
// disagree or one is missing does it look on relays for later identities, one
// npub per query; identities that never published can't be found that way.
// Pure: the caller queries relays and publishes.

import * as nip44 from 'nostr-tools/nip44';
import { type Event, finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import { deriveCounterKey } from './derive';
import { signatureValid } from './marker';

export const COUNTER_KIND = 30078;
/** Constant: the counter key is the user's own, so the address can't be confused. */
export const COUNTER_D = 'nostr-shard-signer/counter';

/** How many indexes past a used one the look-ahead checks (D12). */
export const LOOK_AHEAD = 3;

const isIndex = (n: unknown): n is number =>
  typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;

/** The counter key's pubkey, to query its event. */
export async function counterPubkey(root: Uint8Array): Promise<string> {
  const k = await deriveCounterKey(root);
  try {
    return getPublicKey(k);
  } finally {
    k.fill(0);
  }
}

export const counterFilter = (pubkey: string) => ({
  kinds: [COUNTER_KIND],
  authors: [pubkey],
  '#d': [COUNTER_D],
});

/** A signed counter event saying `next` is the next unused index. */
export async function buildCounter(root: Uint8Array, next: number, now: number): Promise<Event> {
  if (!isIndex(next)) throw new Error(`Bad counter: ${next}`);
  const k = await deriveCounterKey(root);
  try {
    const conversation = nip44.getConversationKey(k, getPublicKey(root));
    return finalizeEvent(
      {
        kind: COUNTER_KIND,
        created_at: now,
        tags: [['d', COUNTER_D]],
        content: nip44.encrypt(JSON.stringify({ v: 1, next }), conversation),
      },
      k
    );
  } finally {
    k.fill(0);
  }
}

/**
 * The highest `next` among the counter key's readable events, or null if none.
 * Not the newest: the counter only grows, so a newer, lower copy (published
 * after a read that missed the latest) must not win (#140).
 */
export async function readCounter(
  events: readonly Event[],
  root: Uint8Array
): Promise<number | null> {
  const pub = await counterPubkey(root);
  const conversation = nip44.getConversationKey(root, pub);
  const mine = events
    .filter(
      (e) =>
        e.pubkey === pub &&
        e.kind === COUNTER_KIND &&
        e.tags.some((t) => t[0] === 'd' && t[1] === COUNTER_D)
    )
    .filter(signatureValid);
  let highest: number | null = null;
  for (const e of mine) {
    try {
      const body = JSON.parse(nip44.decrypt(e.content, conversation)) as {
        v?: unknown;
        next?: unknown;
      };
      if (body.v === 1 && isIndex(body.next)) highest = Math.max(highest ?? 0, body.next);
    } catch {
      // unreadable: the others still count
    }
  }
  return highest;
}

export interface CounterSources {
  readonly relays: number | null;
  readonly evolu: number | null;
  readonly backup: number | null;
}

/** The highest of the three, and whether they all agree (no look-ahead needed then). */
export function highestNext(s: CounterSources): { readonly next: number; readonly agree: boolean } {
  const known = [s.relays, s.evolu, s.backup].filter(isIndex);
  const next = known.length ? Math.max(...known) : 0;
  return { next, agree: known.length === 3 && known.every((n) => n === next) };
}

/**
 * The first index from `start` that is free: no events by its npub, and none
 * by the next `LOOK_AHEAD` either (an index used later means the ones before
 * may have been skipped on another device). `isUsed` queries one npub.
 */
export async function findFreeIndex(
  start: number,
  isUsed: (index: number) => Promise<boolean>,
  lookAhead = LOOK_AHEAD
): Promise<number> {
  let candidate = start;
  for (;;) {
    let lastUsed = -1;
    for (let i = candidate; i < candidate + lookAhead; i++) if (await isUsed(i)) lastUsed = i;
    if (lastUsed < 0) return candidate;
    candidate = lastUsed + 1;
  }
}

/** The next index to use for a new identity (D12). */
export async function nextIndex(
  s: CounterSources,
  isUsed: (index: number) => Promise<boolean>
): Promise<number> {
  const { next, agree } = highestNext(s);
  return agree ? next : findFreeIndex(next, isUsed);
}
