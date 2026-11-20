// Publishing the signer's own events (markers, the counter event, settings;
// #73 D7, D12, D17; #82) to several relays, spaced out and retried on rate
// limits: C13 (#75) saw damus refuse the third event of a quick burst.

import type { Event } from 'nostr-tools/pure';

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
