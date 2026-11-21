// The global list's model (#73 D8, D9; #84), pure: building the list from
// Evolu's rows (globalList.ts reads and writes them).

import { canonicalOrigin } from './derive';

export interface ListedIdentity {
  readonly pubkey: string;
  /** Derivation index; null for stored identities (D9). */
  readonly index: number | null;
  /** Stored identities (D9): the hex secret key, kept under the root; null for derived ones. */
  readonly storedKey: string | null;
  readonly label: string | null;
  /** Canonical origin where it was created. */
  readonly createdOn: string | null;
  readonly usedElsewhere: boolean;
  /** Canonical origins it's paired with. */
  readonly sites: readonly string[];
}

export interface IdentityRow {
  readonly pubkey: string | null;
  readonly derivationIndex: number | null;
  /** Optional in old rows and tests: absent means derived. */
  readonly storedKey?: string | null;
  readonly label: string | null;
  readonly createdOn: string | null;
  readonly usedElsewhere: string | null;
}

export interface PairingRow {
  readonly origin: string | null;
  readonly identityPubkey: string | null;
}

/**
 * The list from Evolu's rows: one entry per pubkey (two devices may have
 * added the same derived identity), derived ones by index, then stored ones.
 */
export function buildList(
  identities: readonly IdentityRow[],
  pairings: readonly PairingRow[]
): ListedIdentity[] {
  const byPubkey = new Map<string, ListedIdentity>();
  for (const r of identities) {
    if (!r.pubkey) continue;
    const had = byPubkey.get(r.pubkey);
    byPubkey.set(r.pubkey, {
      pubkey: r.pubkey,
      index: had?.index ?? r.derivationIndex,
      storedKey: had?.storedKey ?? r.storedKey ?? null,
      label: had?.label ?? r.label,
      createdOn: had?.createdOn ?? r.createdOn,
      usedElsewhere: (had?.usedElsewhere ?? false) || r.usedElsewhere !== null,
      sites: [],
    });
  }
  const sites = new Map<string, Set<string>>();
  for (const p of pairings) {
    if (!p.origin || !p.identityPubkey || !byPubkey.has(p.identityPubkey)) continue;
    const set = sites.get(p.identityPubkey) ?? new Set<string>();
    set.add(p.origin);
    sites.set(p.identityPubkey, set);
  }
  const order = (a: ListedIdentity, b: ListedIdentity) =>
    (a.index ?? Number.MAX_SAFE_INTEGER) - (b.index ?? Number.MAX_SAFE_INTEGER) ||
    a.pubkey.localeCompare(b.pubkey);
  return [...byPubkey.values()]
    .map((i) => ({ ...i, sites: [...(sites.get(i.pubkey) ?? [])].sort() }))
    .sort(order);
}

/** The identities paired with `origin`. */
export const pairedWith = (list: readonly ListedIdentity[], origin: string) => {
  const o = canonicalOrigin(origin);
  return list.filter((i) => i.sites.includes(o));
};

/** The counter as the global list knows it: one past the highest derived index. */
export const listNext = (list: readonly ListedIdentity[]): number | null => {
  const indexes = list.map((i) => i.index).filter((i): i is number => i !== null);
  return indexes.length ? Math.max(...indexes) + 1 : null;
};

export type SyncResult = 'Synced' | 'NoRelays' | 'Syncing' | 'Offline' | 'Error';

/** The global list as the popup uses it (globalList.ts opens it on Evolu). */
export interface GlobalList {
  /** How the first sync went: anything but Synced means the list may be incomplete. */
  readonly synced: SyncResult;
  readonly load: () => Promise<ListedIdentity[]>;
  readonly addDerived: (
    index: number,
    pubkey: string,
    createdOn: string,
    label: string | null
  ) => Promise<void>;
  /** A stored identity (D9: brought over or imported), marked "used elsewhere" from the start. */
  readonly addStored: (
    secretKeyHex: string,
    pubkey: string,
    createdOn: string,
    label: string | null
  ) => Promise<void>;
  readonly pair: (pubkey: string, origin: string) => Promise<void>;
  readonly unpair: (pubkey: string, origin: string) => Promise<void>;
  /** The identity's key was exported or brought in elsewhere (D9, D13): it asks more. */
  readonly markUsedElsewhere: (pubkey: string, index: number | null) => Promise<void>;
  /** Waits for the writes to reach the relay, then closes the database. */
  readonly close: (timeoutMs?: number) => Promise<SyncResult>;
}
