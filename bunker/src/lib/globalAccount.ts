// The global account in the sign-in popup (#73 D8, D12, D15; #84): after the
// global login, the root lives here, in the popup's memory, until it closes.
// Reads the global list and the counter, and does what the user picks:
// pair an identity with the site, create one, unpair one. Then hands the site
// its grant (siteGrant.ts). No JSX: GlobalSignInPopupView renders it.

import type { Event, Filter } from 'nostr-tools';
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import { buildBackupFile } from './backupFile';
import { buildCounter, counterFilter, counterPubkey, nextIndex, readCounter } from './counter';
import { canonicalOrigin, deriveIdentity, deriveRoot } from './derive';
import { type GlobalList, type ListedIdentity, listNext, pairedWith } from './globalListModel';
import { grantFromRoot } from './identity';
import { buildMarker, type MarkerReading, markerFilter, readMarker } from './marker';
import { exportMasterKey } from './masterKey';
import type { SiteGrant } from './siteGrant';

export interface AccountDeps {
  /** Opens the global list for the root (Evolu in memory, globalList.ts). */
  readonly openList: (root: Uint8Array) => Promise<GlobalList>;
  /** Events matching a filter on the signer's relays; null when none answered. */
  readonly query: (filter: Filter) => Promise<Event[] | null>;
  /** Publishes the signer's own events (relayPublish.ts). */
  readonly publish: (events: Event[]) => Promise<void>;
  readonly now?: () => number;
  /** Own-clientId sites: this site login's marker address (D7), from the widget. */
  readonly markerAddress?: string;
}

export interface GlobalAccount {
  /** Every identity of the account, with where it's paired. */
  readonly list: readonly ListedIdentity[];
  /** The identities already paired with this site. */
  readonly paired: readonly ListedIdentity[];
  /** False when Evolu didn't sync: names and pairings may be missing (never identities). */
  readonly complete: boolean;
  /** A first sign-in: no identity known anywhere. */
  readonly isNew: boolean;
  readonly pair: (pubkey: string) => Promise<void>;
  readonly unpair: (pubkey: string) => Promise<void>;
  /**
   * Creates the next identity (D12), paired with this site. With `profile`
   * (D15: the user chose to use their Google name and picture), its kind-0
   * profile is published.
   */
  readonly create: (label: string | null, profile?: NewProfile) => Promise<ListedIdentity>;
  /** The site's grant with `activePubkey` active; the identity must be paired. */
  readonly grant: (activePubkey: string) => Promise<SiteGrant>;
  /** The master key as text (D10): NIP-49 with a password, else nsec. */
  readonly exportMasterKey: (password?: string) => string;
  /** The encrypted backup file (D10), as JSON text. */
  readonly backupFile: () => Promise<string>;
  /**
   * Own-clientId sites: what the marker at this site login's address says (D7):
   * null without an address; 'none', 'paired', 'unpaired', 'not-yours'
   * (another global account's, or forged) or 'unreadable'.
   */
  readonly markerStatus: MarkerReading['status'] | null;
  /**
   * The signed marker to hand the site (JSON): the current "paired" one, or a
   * new one if there's none yet or it says "unpaired" (published first).
   * Undefined without an address.
   */
  readonly siteMarker: () => Promise<string | undefined>;
  /** Leaving the global account on this site: a newer "unpaired" marker, published (D7). */
  readonly leaveSite: () => Promise<void>;
  /**
   * "Use this account on other sites" (D9): a site-only account's key becomes
   * a stored identity, marked "used elsewhere", created on this site and not
   * paired with it (its own site keeps using the site login). Its pubkey.
   */
  readonly addStored: (secretKeyHex: string) => Promise<string>;
  /** Waits for the list to sync, then wipes the root. */
  readonly close: () => Promise<void>;
}

export interface NewProfile {
  readonly name?: string;
  readonly picture?: string;
}

const nowS = () => Math.floor(Date.now() / 1000);

/**
 * Opens the account for `site` from the global login key (wiped here). The
 * root stays inside the returned object until `close`.
 */
export async function openGlobalAccount(
  loginKey: Uint8Array,
  site: string,
  deps: AccountDeps
): Promise<GlobalAccount> {
  const origin = canonicalOrigin(site);
  const root = await deriveRoot(loginKey);
  loginKey.fill(0);
  const now = deps.now ?? nowS;
  const list = await deps.openList(root);
  const counterPub = await counterPubkey(root);
  const address = deps.markerAddress;
  const [rows, counterEvents, markerEvents] = await Promise.all([
    list.load(),
    deps.query(counterFilter(counterPub)),
    address ? deps.query(markerFilter(address)) : Promise.resolve(null),
  ]);
  let marker: MarkerReading | null = address
    ? await readMarker(markerEvents ?? [], root, origin, address)
    : null;
  /** A marker newer than the one at the address, so relays keep it (D7, C13). */
  const writeMarker = async (state: 'paired' | 'unpaired') => {
    if (!address) return undefined;
    const previous = marker && 'event' in marker ? marker.event.created_at : 0;
    const event = await buildMarker(root, origin, address, state, Math.max(now(), previous + 1));
    await deps.publish([event]);
    marker = { status: state, event };
    return JSON.stringify(event);
  };
  let current = rows;
  const relayCounter = counterEvents ? await readCounter(counterEvents, root) : null;

  const pubkeyOf = async (index: number) => {
    const k = await deriveIdentity(root, index);
    try {
      return getPublicKey(k);
    } finally {
      k.fill(0);
    }
  };
  const usedOnRelays = async (index: number) =>
    ((await deps.query({ authors: [await pubkeyOf(index)], limit: 1 })) ?? []).length > 0;
  const reload = async () => {
    current = await list.load();
  };
  const find = (pubkey: string) => current.find((i) => i.pubkey === pubkey);

  const create = async (label: string | null, profile?: NewProfile) => {
    // TODO(#87): the backup's counter joins these sources.
    const index = await nextIndex(
      { relays: relayCounter, evolu: listNext(current), backup: null },
      usedOnRelays
    );
    const pubkey = await pubkeyOf(index);
    await list.addDerived(index, pubkey, origin, label);
    await list.pair(pubkey, origin);
    // Relays keep only the newest counter: never publish one without having
    // read theirs, or a lower value could replace a higher one.
    const events = counterEvents ? [await buildCounter(root, index + 1, now())] : [];
    if (profile && (profile.name || profile.picture)) {
      const k = await deriveIdentity(root, index);
      events.push(
        finalizeEvent({ kind: 0, created_at: now(), tags: [], content: JSON.stringify(profile) }, k)
      );
      k.fill(0);
    }
    if (events.length) await deps.publish(events);
    await reload();
    return (
      find(pubkey) ?? {
        pubkey,
        index,
        label,
        createdOn: origin,
        storedKey: null,
        usedElsewhere: false,
        sites: [origin],
      }
    );
  };

  // A first sign-in, or a new device that didn't sync: identity 0 exists for
  // sure (it's derived), so it's listed even without Evolu (never a second
  // account, D5).
  const isNew = current.length === 0 && relayCounter === null;
  if (current.length === 0) {
    const pubkey0 = await pubkeyOf(0);
    current = [
      {
        pubkey: pubkey0,
        index: 0,
        storedKey: null,
        label: null,
        createdOn: null,
        usedElsewhere: false,
        sites: [],
      },
    ];
  }

  return {
    get list() {
      return current;
    },
    get paired() {
      return pairedWith(current, origin);
    },
    complete: list.synced === 'Synced',
    isNew,
    pair: async (pubkey) => {
      const i = find(pubkey);
      if (!i) throw new Error('Not an identity of this account');
      // Identity 0 on a first sign-in (or an unsynced device) isn't in Evolu yet.
      const known = (await list.load()).some((r) => r.pubkey === pubkey);
      if (!known && i.index !== null)
        await list.addDerived(i.index, pubkey, i.createdOn ?? origin, i.label);
      await list.pair(pubkey, origin);
      await reload();
    },
    unpair: async (pubkey) => {
      await list.unpair(pubkey, origin);
      await reload();
    },
    create,
    grant: async (activePubkey) => {
      const chosen = pairedWith(current, origin).filter(
        (i) => i.index !== null || i.storedKey !== null
      );
      if (!chosen.some((i) => i.pubkey === activePubkey))
        throw new Error('That identity is not paired with this site');
      return grantFromRoot(
        root,
        origin,
        chosen.map((i) =>
          i.storedKey !== null
            ? { storedKey: i.storedKey, label: i.label }
            : { index: i.index as number, label: i.label }
        ),
        activePubkey
      );
    },
    get markerStatus() {
      return marker?.status ?? null;
    },
    siteMarker: async () => {
      if (!address) return undefined;
      if (marker?.status === 'paired') return JSON.stringify(marker.event);
      return writeMarker('paired');
    },
    addStored: async (secretKeyHex) => {
      const pubkey = getPublicKey(
        Uint8Array.from(secretKeyHex.match(/../g) ?? [], (x) => Number.parseInt(x, 16))
      );
      if (!find(pubkey)) await list.addStored(secretKeyHex, pubkey, origin, null);
      await reload();
      return pubkey;
    },
    leaveSite: async () => {
      await writeMarker('unpaired');
    },
    exportMasterKey: (password) => exportMasterKey(root, password),
    backupFile: () =>
      buildBackupFile({
        v: 1,
        root: Array.from(root, (x) => x.toString(16).padStart(2, '0')).join(''),
        counter: Math.max(relayCounter ?? 0, listNext(current) ?? 0, 1),
        identities: current,
        createdAt: new Date(now() * 1000).toISOString(),
      }),
    close: async () => {
      try {
        await list.close();
      } finally {
        root.fill(0);
      }
    },
  };
}
