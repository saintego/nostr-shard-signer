// An encrypted copy of the account's list on the user's relays (#147). The
// global list's only lasting copy is on Evolu's relay, which may be wiped, and
// Safari wipes the device's (C8 day 8). This copy brings back the derived
// identities (index, name, where created) and which sites each is used on.
//
// Bookkeeping only, never a key: no stored identities (their keys are in the
// backup file, #137) and no link records (relisted when that sign-in is used,
// #142). Signed by the counter key (root-derived, unlinkable) at its own `d`,
// content NIP-44 encrypted to the root, like the counter (D12).

import type { Event, Filter } from 'nostr-tools';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import { COUNTER_KIND } from './counter';
import { deriveCounterKey, deriveIdentity } from './derive';
import type { ListedIdentity } from './globalListModel';
import { newestFirst, signatureValid } from './marker';

export const LIST_D = 'nostr-shard-signer/list';
/** NIP-44 encrypts at most 65535 bytes; past that no copy is written. */
const MAX_PLAIN = 60_000;

export interface CopiedIdentity {
  readonly index: number;
  readonly pubkey: string;
  readonly label: string | null;
  readonly createdOn: string | null;
  readonly sites: readonly string[];
}

export interface ListCopy {
  readonly v: 1;
  readonly identities: readonly CopiedIdentity[];
}

export const listCopyFilter = (counterPubkey: string): Filter => ({
  kinds: [COUNTER_KIND],
  authors: [counterPubkey],
  '#d': [LIST_D],
});

/** The copy of a list: derived identities only, without any key. */
export const listCopyOf = (list: readonly ListedIdentity[]): ListCopy => ({
  v: 1,
  identities: list
    .filter((i) => i.index !== null && i.storedKey === null)
    .map((i) => ({
      index: i.index as number,
      pubkey: i.pubkey,
      label: i.label,
      createdOn: i.createdOn,
      sites: [...i.sites],
    })),
});

/** The signed copy event, or null when it would be too large to encrypt. */
export async function buildListCopy(
  root: Uint8Array,
  copy: ListCopy,
  createdAt: number
): Promise<Event | null> {
  const plain = JSON.stringify(copy);
  if (new TextEncoder().encode(plain).length > MAX_PLAIN) return null;
  const k = await deriveCounterKey(root);
  try {
    const conversation = nip44.getConversationKey(k, getPublicKey(root));
    return finalizeEvent(
      {
        kind: COUNTER_KIND,
        created_at: createdAt,
        tags: [['d', LIST_D]],
        content: nip44.encrypt(plain, conversation),
      },
      k
    );
  } finally {
    k.fill(0);
  }
}

const isText = (s: unknown, max: number): s is string => typeof s === 'string' && s.length <= max;

/** One identity from the copy, if well formed and really the root's identity at that index. */
async function checked(root: Uint8Array, value: unknown): Promise<CopiedIdentity | null> {
  const v = value as Partial<CopiedIdentity> | null;
  if (!v || typeof v.index !== 'number' || !Number.isSafeInteger(v.index) || v.index < 0)
    return null;
  if (v.index > 10_000 || !isText(v.pubkey, 64)) return null;
  const k = await deriveIdentity(root, v.index);
  const pubkey = getPublicKey(k);
  k.fill(0);
  if (pubkey !== v.pubkey) return null;
  const sites = Array.isArray(v.sites) ? v.sites.filter((s) => isText(s, 300)) : [];
  return {
    index: v.index,
    pubkey,
    label: isText(v.label, 100) ? v.label : null,
    createdOn: isText(v.createdOn, 300) ? v.createdOn : null,
    sites,
  };
}

/** The newest readable copy among `events` (by the counter key), with its event; null if none. */
export async function readListCopy(
  events: readonly Event[],
  root: Uint8Array,
  counterPubkey: string
): Promise<{ readonly copy: ListCopy; readonly event: Event } | null> {
  const conversation = nip44.getConversationKey(root, counterPubkey);
  const mine = events
    .filter(
      (e) =>
        e.pubkey === counterPubkey &&
        e.kind === COUNTER_KIND &&
        e.tags.some((t) => t[0] === 'd' && t[1] === LIST_D)
    )
    .filter(signatureValid)
    .sort(newestFirst);
  for (const event of mine) {
    try {
      const body = JSON.parse(nip44.decrypt(event.content, conversation)) as Partial<ListCopy>;
      if (body.v !== 1 || !Array.isArray(body.identities)) continue;
      const identities: CopiedIdentity[] = [];
      for (const i of body.identities.slice(0, 1000)) {
        const ok = await checked(root, i);
        if (ok) identities.push(ok);
      }
      return { copy: { v: 1, identities }, event };
    } catch {
      // unreadable: try an older one
    }
  }
  return null;
}

/** The identities as the list shows them, from a copy (no keys, not used elsewhere). */
export const listedFromCopy = (copy: ListCopy): ListedIdentity[] =>
  copy.identities.map((i) => ({
    pubkey: i.pubkey,
    index: i.index,
    storedKey: null,
    label: i.label,
    createdOn: i.createdOn,
    usedElsewhere: false,
    sites: i.sites,
  }));
