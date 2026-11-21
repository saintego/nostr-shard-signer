// Markers (#73 D7, #82): a note on Nostr that a site's own login is linked to
// the global account. Pure: builds and reads events; the caller publishes
// (relayPublish.ts), queries and keeps the signed event in the site's store.
//
//   - signed by the site's marker key (from the root, not the site login);
//   - at the address `30078:<marker key>:<d>`, where d comes from the site
//     login's secret (derive.ts), so the site's sign-in can find it with
//     `#d` alone, without the global account;
//   - all content NIP-44 encrypted to the root: only the global account reads it.
//
// Without the root, any event with that `d` tag is only a hint ("a note was
// found"): the site's owner knows the address and can publish anything there.
// With the root, only the marker key's newest event counts.

import * as nip44 from 'nostr-tools/nip44';
import { type Event, finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { canonicalOrigin, deriveMarkerKey } from './derive';

export const MARKER_KIND = 30078;

export type MarkerState = 'paired' | 'unpaired';

/** What the encrypted content holds. */
interface MarkerBody {
  readonly v: 1;
  readonly state: MarkerState;
  readonly origin: string;
}

/** The relay filter that finds a site's marker without the root. */
export const markerFilter = (address: string) => ({ kinds: [MARKER_KIND], '#d': [address] });

/** The newest event first (NIP-01: later created_at, then lower id). */
export const newestFirst = (a: Event, b: Event) =>
  b.created_at - a.created_at || (a.id < b.id ? -1 : 1);

/**
 * Checks the signature itself: nostr-tools caches "verified" on the event
 * object (a symbol that object spread copies), so verify a clean copy.
 */
export const signatureValid = (e: Event) => verifyEvent(structuredClone(e));

const dOf = (e: Event) => e.tags.find((t) => t[0] === 'd')?.[1];

/**
 * A signed marker for `origin`. `now` must be later than the previous version's
 * date so relays keep this one (unpairing replaces pairing). The marker key is
 * wiped; the root is the caller's.
 */
export async function buildMarker(
  root: Uint8Array,
  origin: string,
  address: string,
  state: MarkerState,
  now: number
): Promise<Event> {
  const markerKey = await deriveMarkerKey(root, origin);
  try {
    const body: MarkerBody = { v: 1, state, origin: canonicalOrigin(origin) };
    const conversation = nip44.getConversationKey(markerKey, getPublicKey(root));
    return finalizeEvent(
      {
        kind: MARKER_KIND,
        created_at: now,
        tags: [['d', address]],
        content: nip44.encrypt(JSON.stringify(body), conversation),
      },
      markerKey
    );
  } finally {
    markerKey.fill(0);
  }
}

/** What the site's sign-in sees without the root. */
export type MarkerHint =
  | { readonly found: false }
  | { readonly found: true; readonly eventId: string };

/** Without the root: is there any note at the address? ("a note was found", D5). */
export function markerHint(events: readonly Event[], address: string): MarkerHint {
  const at = events
    .filter((e) => e.kind === MARKER_KIND && dOf(e) === address)
    .sort(newestFirst)[0];
  return at ? { found: true, eventId: at.id } : { found: false };
}

/** What the global sign-in reads, with the root. */
export type MarkerReading =
  | { readonly status: 'none' }
  /** The marker key's own newest version: paired or unpaired, and the event to keep. */
  | { readonly status: MarkerState; readonly event: Event }
  /** Only events from other keys or with bad signatures: another global account's, or forged ("this note wasn't yours"). */
  | { readonly status: 'not-yours'; readonly authors: readonly string[] }
  /** Signed by the marker key but unreadable or for another origin: reported, not trusted. */
  | { readonly status: 'unreadable'; readonly event: Event };

export async function readMarker(
  events: readonly Event[],
  root: Uint8Array,
  origin: string,
  address: string
): Promise<MarkerReading> {
  const markerKey = await deriveMarkerKey(root, origin);
  try {
    const markerPub = getPublicKey(markerKey);
    const at = events.filter((e) => e.kind === MARKER_KIND && dOf(e) === address);
    const valid = (e: Event) => e.pubkey === markerPub && signatureValid(e);
    const mine = at.filter(valid).sort(newestFirst)[0];
    if (!mine) {
      const authors = [...new Set(at.filter((e) => !valid(e)).map((e) => e.pubkey))];
      return authors.length ? { status: 'not-yours', authors } : { status: 'none' };
    }
    try {
      const conversation = nip44.getConversationKey(root, markerPub);
      const body = JSON.parse(nip44.decrypt(mine.content, conversation)) as Partial<MarkerBody>;
      const readable = body.v === 1 && (body.state === 'paired' || body.state === 'unpaired');
      if (!readable || body.origin !== canonicalOrigin(origin))
        return { status: 'unreadable', event: mine };
      return { status: body.state as MarkerState, event: mine };
    } catch {
      return { status: 'unreadable', event: mine };
    }
  } finally {
    markerKey.fill(0);
  }
}
