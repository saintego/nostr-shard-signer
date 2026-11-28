// Signed copies of the account's Nostr events in the backup file (#146).
// Relays may drop events, and some of the signer's have no other copy. Signed
// events can be sent to relays again unchanged, so /restore needs no key to
// put them back ("Publish again"), and a relay holding a newer version keeps
// it (newest wins).

import type { Event, Filter } from 'nostr-tools';
import { verifyEvent } from 'nostr-tools/pure';
import { isProtectedEvent } from '../vendor/evolustr/evolustr.js';
import { counterFilter } from './counter';

/** The most events a backup keeps (a few kB each at most). */
const MAX_EVENTS = 200;
/** Kinds kept per identity: profile, follow list, relay list. */
const PROFILE_KINDS = [0, 3, 10002];

export interface BackupEvents {
  /** Evolustr vaults, the counter, profiles, follows and relay lists. */
  readonly events: readonly Event[];
  /** Link pointers (D25), apart: an old one could bring back a removed link. */
  readonly pointers: readonly Event[];
}

/** On a clean copy: nostr-tools caches "verified" on the object, and a spread keeps it. */
const validSignature = (e: Event) => verifyEvent(JSON.parse(JSON.stringify(e)) as Event);

const dOf = (e: Event) => e.tags.find((t) => t[0] === 'd')?.[1] ?? '';
const addressOf = (e: Event) => `${e.kind}:${e.pubkey}:${e.kind >= 30000 ? dOf(e) : ''}`;

/** The newest valid event per address (NIP-01: newest wins; the lowest id on a tie). */
export function newestPerAddress(events: readonly Event[]): Event[] {
  const best = new Map<string, Event>();
  for (const e of events) {
    if (!validSignature(e)) continue;
    const a = addressOf(e);
    const had = best.get(a);
    if (!had || e.created_at > had.created_at || (e.created_at === had.created_at && e.id < had.id))
      best.set(a, e);
  }
  return [...best.values()];
}

/**
 * What the backup keeps: read from every relay (`query`), the account's
 * Evolustr vaults, its counter, and each identity's profile, follows and
 * relay list; the link pointers come from the list's records (their latest
 * version, "unlinked" included). Relays that don't answer just give less.
 */
export async function collectBackupEvents(
  counterPubkey: string,
  identityPubkeys: readonly string[],
  pointerEvents: readonly string[],
  query: (filter: Filter) => Promise<Event[] | null>
): Promise<BackupEvents> {
  const authors = [...new Set(identityPubkeys)];
  const [counter, profiles, appData] = await Promise.all([
    query(counterFilter(counterPubkey)),
    authors.length ? query({ kinds: PROFILE_KINDS, authors }) : Promise.resolve([]),
    authors.length ? query({ kinds: [30078], authors }) : Promise.resolve([]),
  ]);
  const vaults = (appData ?? []).filter((e) =>
    isProtectedEvent({ kind: e.kind, tags: e.tags as string[][] })
  );
  const events = newestPerAddress([...(counter ?? []), ...vaults, ...(profiles ?? [])]).slice(
    0,
    MAX_EVENTS
  );
  const pointers: Event[] = [];
  for (const json of pointerEvents) {
    try {
      pointers.push(JSON.parse(json) as Event);
    } catch {
      // a record rebuilt without its event (#142): nothing to keep
    }
  }
  return { events, pointers: newestPerAddress(pointers) };
}

/** Days after which a backup's link pointers are left out unless the user asks (#146). */
export const POINTERS_FRESH_DAYS = 30;

/**
 * What "Publish again" sends: every kept event, and the link pointers only
 * when the backup is recent or the user chose to. An old pointer can bring
 * back a link removed after the backup, if relays lost the newer one.
 */
export function eventsToPublish(
  kept: BackupEvents,
  backupAt: string,
  now: number,
  includeOldPointers: boolean
): Event[] {
  const ageDays = (now - Date.parse(backupAt)) / 86_400_000;
  const pointers = ageDays <= POINTERS_FRESH_DAYS || includeOldPointers ? kept.pointers : [];
  return [...kept.events, ...pointers].filter((e) => validSignature(e));
}
