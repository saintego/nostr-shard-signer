// Publishing the signer's own events (markers, the counter event, settings;
// #73 D7, D12, D17; #82) to several relays, spaced out and retried on rate
// limits: C13 (#75) saw damus refuse the third event of a quick burst.

import { type Filter, SimplePool } from 'nostr-tools';
import type { Event } from 'nostr-tools/pure';
import { publishToRelay } from './nostr';
import { firstAnswers } from './quorum';

/**
 * Relays for the signer's own events: the ones that kept markers, the counter
 * and settings in C13 (16 min). nostr.oxtr.dev and relay.nostr.band failed.
 * TODO(#82): confirm from C13 retention (1 day, 1 week, 1 month).
 */
export const SIGNER_RELAYS = [
  'wss://nos.lol',
  'wss://relay.primal.net',
  'wss://nostr.mom',
  'wss://nostr.bitcoiner.social',
  'wss://offchain.pub',
  'wss://relay.damus.io',
] as const;

/** How a relay answered. `newer`: it holds a newer version, so this one isn't needed (D7). */
export type PublishStatus = 'ok' | 'newer' | 'failed';

export interface PublishResult {
  readonly relay: string;
  readonly eventId: string;
  readonly status: PublishStatus;
  readonly error?: string;
}

export interface PublishOptions {
  /** Sends one event to one relay; rejects with the relay's message. */
  readonly publishOne: (relay: string, event: Event) => Promise<void>;
  /** Pause between two events to the same relay, and the first backoff after a rate limit. */
  readonly spacingMs?: number;
  /** Retries per event and relay after a rate limit. */
  readonly retries?: number;
  readonly sleep?: (ms: number) => Promise<void>;
}

const isRateLimit = (msg: string) => /rate-?limit|too much|too many|slow down/i.test(msg);
/** Already there (NIP-01 `duplicate:`). */
const isDuplicate = (msg: string) => /^duplicate:/i.test(msg);
/** The relay holds a newer version at this address ("have newer event" in C13). */
const isNewer = (msg: string) => /newer/i.test(msg);

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function publishTo(
  relay: string,
  event: Event,
  o: Required<PublishOptions>
): Promise<PublishResult> {
  const result = (status: PublishStatus, error?: string): PublishResult =>
    error === undefined
      ? { relay, eventId: event.id, status }
      : { relay, eventId: event.id, status, error };
  for (let attempt = 0; ; attempt++) {
    try {
      await o.publishOne(relay, event);
      return result('ok');
    } catch (e) {
      const msg = (e as Error)?.message ?? String(e);
      if (isDuplicate(msg)) return result('ok');
      if (isNewer(msg)) return result('newer', msg);
      if (!isRateLimit(msg) || attempt >= o.retries) return result('failed', msg);
      await o.sleep(o.spacingMs * 2 ** (attempt + 1));
    }
  }
}

/**
 * Publishes `events` to every relay: relays in parallel, events to one relay
 * one at a time and spaced out, retried with backoff on a rate limit. Never
 * throws; one result per event and relay.
 */
export async function publishSpaced(
  events: readonly Event[],
  relays: readonly string[],
  options: PublishOptions
): Promise<PublishResult[]> {
  const o: Required<PublishOptions> = {
    spacingMs: 1500,
    retries: 2,
    sleep: defaultSleep,
    ...options,
  };
  const perRelay = await Promise.all(
    relays.map(async (relay) => {
      const results: PublishResult[] = [];
      for (const [i, event] of events.entries()) {
        if (i > 0) await o.sleep(o.spacingMs);
        results.push(await publishTo(relay, event, o));
      }
      return results;
    })
  );
  return perRelay.flat();
}

/** Whether enough relays hold `eventId` (or a newer version) to count as published. */
export const published = (results: readonly PublishResult[], eventId: string, atLeast = 2) => {
  const mine = results.filter((r) => r.eventId === eventId);
  return (
    mine.length > 0 &&
    mine.filter((r) => r.status !== 'failed').length >= Math.min(atLeast, mine.length)
  );
};

const QUERY_WAIT_MS = 4000;
/** Relays that must answer before a read stops waiting for the others (#111). */
export const QUERY_QUORUM = 3;
/** Relays that must answer before "nothing there" is believed (D5, #139). */
export const MIN_EMPTY_ANSWERS = 2;

/** One relay's events for `filter`: resolves at its EOSE, rejects if it closes first. */
function queryOne(pool: SimplePool, relay: string, filter: Filter): Promise<Event[]> {
  return new Promise((resolve, reject) => {
    const events: Event[] = [];
    const sub = pool.subscribeMany([relay], filter, {
      onevent: (e) => events.push(e),
      oneose: () => {
        sub.close();
        resolve(events);
      },
      onclose: (reasons) => reject(new Error(reasons.join('; '))),
      // No maxWait: nostr-tools reports a timeout as EOSE, which would count a
      // silent relay as "nothing there". firstAnswers caps the wait instead.
    });
  });
}

/**
 * What relays' answers say: their events (deduplicated), [] when at least
 * MIN_EMPTY_ANSWERS relays (or all of them, if fewer) answered with none, and
 * null otherwise: one relay may lag or have dropped it (#139, #141).
 */
export function readAnswers(
  answers: readonly (readonly Event[])[],
  relayCount: number
): Event[] | null {
  const byId = new Map(answers.flat().map((e) => [e.id, e]));
  if (byId.size > 0) return [...byId.values()];
  return answers.length > 0 && answers.length >= Math.min(MIN_EMPTY_ANSWERS, relayCount)
    ? []
    : null;
}

/**
 * Events matching `filter`, once QUERY_QUORUM relays have answered (a slow
 * relay isn't waited for, #111), or what answered within QUERY_WAIT_MS. With
 * `all`, it waits for every relay up to QUERY_WAIT_MS: for a read a write
 * builds on, e.g. before publishing a counter (#140).
 *
 * Null when it can't say: no event and fewer than MIN_EMPTY_ANSWERS relays
 * answered (#139). Then the caller mustn't assume there are none.
 */
export async function queryRelays(
  filter: Filter,
  relays: readonly string[] = SIGNER_RELAYS,
  opts: { readonly all?: boolean } = {}
): Promise<Event[] | null> {
  const pool = new SimplePool();
  try {
    const answers = await firstAnswers(
      relays.map((relay) => () => queryOne(pool, relay, filter)),
      opts.all ? relays.length : Math.min(QUERY_QUORUM, relays.length),
      QUERY_WAIT_MS
    );
    return readAnswers(answers, relays.length);
  } finally {
    pool.destroy();
  }
}

/** Publishes the signer's own events to SIGNER_RELAYS, spaced out (never throws). */
export const publishToSignerRelays = async (events: Event[]): Promise<void> => {
  await publishSpaced(events, SIGNER_RELAYS, { publishOne: publishToRelay });
};
