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
import { type Primary, pointerAddress } from './envelope';
import {
  type GlobalList,
  type LinkRecord,
  type ListedIdentity,
  listNext,
  pairedWith,
} from './globalListModel';
import { grantFromRoot } from './identity';
import {
  type LinkingDeps,
  type LinkScope,
  type Login,
  rebuiltLinkRecord,
  sealLink,
  storedPointers,
  unlinkRecord,
} from './linking';
import { buildMarker, type MarkerReading, markerFilter, readMarker } from './marker';
import { exportMasterKey } from './masterKey';
import type { SiteGrant } from './siteGrant';

export interface AccountDeps {
  /** Opens the global list for the root (Evolu in memory, globalList.ts). */
  readonly openList: (root: Uint8Array) => Promise<GlobalList>;
  /** Events matching a filter on the signer's relays; null when they can't say (#139). */
  readonly query: (filter: Filter) => Promise<Event[] | null>;
  /** The same, waiting for every relay: before a write that builds on it (#140). Default: `query`. */
  readonly queryAll?: (filter: Filter) => Promise<Event[] | null>;
  /** Publishes the signer's own events (relayPublish.ts). */
  readonly publish: (events: Event[]) => Promise<void>;
  readonly now?: () => number;
  /** Own-clientId sites: this site login's marker address (D7), from the widget. */
  readonly markerAddress?: string;
  /** Linking (D25, #98): a linked login's own Evolu database. */
  readonly openCopies?: LinkingDeps['openCopies'];
  /** Who created the account (D25): the primary provider, masked. */
  readonly primary?: Primary;
  /** Signed in through an envelope: that login's pointer pubkey. */
  readonly viaPointer?: string;
  /** That login and its envelope's version: to list the link again if the list lost it (#142). */
  readonly viaLogin?: { readonly login: Login; readonly version: number };
  /** Background work to wait for later (LinkingDeps.defer, #110). */
  readonly defer?: (work: Promise<unknown>) => void;
  /** The lookup already found this account (lookUp's `own`): never new (#136). */
  readonly knownExisting?: boolean;
  /**
   * The lookup answered in full and found nothing, not even an event by
   * identity 0 (resolve's "none"): new without checking again, and identity 0
   * has no profile.
   */
  readonly provenNew?: boolean;
}

export interface GlobalAccount {
  /** Every identity of the account, with where it's paired. */
  readonly list: readonly ListedIdentity[];
  /** The identities already paired with this site. */
  readonly paired: readonly ListedIdentity[];
  /** False when Evolu didn't sync: names and pairings may be missing (never identities). */
  readonly complete: boolean;
  /**
   * A first sign-in, proven (#136): the list is empty and synced, the relays
   * answered without a counter, and the lookup found nothing.
   */
  readonly isNew: boolean;
  /** Not new, yet the list is empty: Evolu's copy was lost or didn't sync (#136, #137). */
  readonly listMissing: boolean;
  /**
   * The list is missing, and the relays' counter says the account only ever
   * had identity 0: it can be used again without asking (no other identity to
   * keep apart from it, #136).
   */
  readonly onlyIdentity0: boolean;
  /** The identity has no profile (kind 0) on relays that answered: one may be offered (#136). */
  readonly profileFree: (pubkey: string) => Promise<boolean>;
  readonly pair: (pubkey: string) => Promise<void>;
  /**
   * Publishes a name and picture (kind 0) for one of the account's identities
   * (D15), only when it has no profile yet (#136): false when it didn't.
   */
  readonly publishProfile: (pubkey: string, profile: NewProfile) => Promise<boolean>;
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
  /** The provider the account was created with (D25), when known. */
  readonly primary: Primary | null;
  /** Linked sign-ins (D25), linked and unlinked. */
  readonly links: readonly LinkRecord[];
  /** Signed in through a sign-in this account unlinked: when (ISO), else null (review 8, item 3). */
  readonly unlinkedVia: string | null;
  /** This sign-in opened the account but wasn't listed; it is now (#142). */
  readonly relistedLink: { readonly provider: string; readonly masked: string } | null;
  /**
   * Links another sign-in (proven in this popup session) to this account:
   * 'full', or a restricted link to these identities (pubkeys, #98).
   */
  /**
   * Links `login`. `after`: the version of an envelope it already has (a link
   * left half-done), so the new one is newer.
   */
  readonly link: (login: Login, scope: 'full' | readonly string[], after?: number) => Promise<void>;
  /** Whether `rootHex` is this account's root (an envelope that opens this account). */
  readonly isRoot: (rootHex: string) => boolean;
  /** Unlinks a sign-in from this session, with the stored keys (review 8, item 3). */
  readonly unlink: (pointerPubkey: string) => Promise<void>;
  /** Waits for the list to sync, then wipes the root. */
  readonly close: () => Promise<void>;
}

export interface NewProfile {
  readonly name?: string;
  readonly picture?: string;
}

const toHexKey = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHexKey = (h: string) =>
  Uint8Array.from(h.match(/../g) ?? [], (x) => Number.parseInt(x, 16));

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
  const root = await deriveRoot(loginKey);
  loginKey.fill(0);
  return openGlobalAccountFromRoot(root, site, deps);
}

/**
 * Opens the account from its root: derived from the primary login, or opened
 * from a linked sign-in's envelope (D25). The root is kept (and wiped at
 * `close`): pass a copy if the caller keeps its own.
 */
export async function openGlobalAccountFromRoot(
  root: Uint8Array,
  site: string,
  deps: AccountDeps
): Promise<GlobalAccount> {
  const origin = canonicalOrigin(site);
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
  let links = await list.links();
  const linkingDeps = (): LinkingDeps => {
    if (!deps.openCopies) throw new Error('Linking needs the envelope store');
    return {
      query: deps.query,
      publish: deps.publish,
      openCopies: deps.openCopies,
      openList: deps.openList,
      now,
      ...(deps.defer ? { defer: deps.defer } : {}),
    };
  };
  /** The identities a restricted link opens, with their keys (derived, or stored). */
  const linkScope = async (scope: 'full' | readonly string[]): Promise<LinkScope> => {
    if (scope === 'full') return { kind: 'full' };
    const identities = [];
    for (const pubkey of scope) {
      const i = current.find((x) => x.pubkey === pubkey);
      if (!i) throw new Error('Not an identity of this account');
      const key = i.storedKey ? fromHexKey(i.storedKey) : await deriveIdentity(root, i.index ?? 0);
      identities.push({ secretKey: toHexKey(key), pubkey, index: i.index, label: i.label });
      key.fill(0);
    }
    return { kind: 'restricted', identities };
  };
  // Re-send the stored pointers, linked and unlinked (review 8, item 9).
  if (links.length) void deps.publish(storedPointers(links)).catch(() => {});
  let via = deps.viaPointer ? links.find((l) => l.pointerPubkey === deps.viaPointer) : undefined;
  // A full link that opened the account isn't in the synced list (a link left
  // half-done, or a lost list): list it again, so it can be seen and unlinked
  // (#142). Not from an unsynced list, which would add duplicates.
  let relistedLink: GlobalAccount['relistedLink'] = null;
  const listSynced = list.synced === 'Synced' || list.synced === 'NoRelays';
  if (!via && deps.viaLogin && listSynced) {
    const record = await rebuiltLinkRecord(deps.viaLogin.login, deps.viaLogin.version, now());
    await list.saveLink(record);
    links = await list.links();
    via = links.find((l) => l.pointerPubkey === record.pointerPubkey);
    relistedLink = { provider: record.provider, masked: record.masked };
  }
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

  /**
   * The counter from every relay (#140): what a counter write builds on.
   * Undefined when the relays can't say; then no counter is written.
   */
  const fullCounter = async (): Promise<number | null | undefined> => {
    const events = await (deps.queryAll ?? deps.query)(counterFilter(counterPub));
    return events === null ? undefined : readCounter(events, root);
  };
  /** Publishes the counter: at least `next`, never below what any relay holds (D12, #140). */
  const writeCounter = async (next: number, seen?: number | null) => {
    const known = seen === undefined ? await fullCounter() : seen;
    if (known === undefined) return; // can't read every relay: retried at a later sign-in
    await deps.publish([await buildCounter(root, Math.max(next, known ?? 0), now())]);
  };

  const create = async (label: string | null, profile?: NewProfile) => {
    // A write follows: read the counter from every relay first (#140).
    const relays = await fullCounter();
    // TODO(#87): the backup's counter joins these sources.
    const index = await nextIndex(
      {
        relays: relays === undefined ? relayCounter : relays,
        evolu: listNext(current),
        backup: null,
      },
      usedOnRelays
    );
    const pubkey = await pubkeyOf(index);
    await list.addDerived(index, pubkey, origin, label);
    await list.pair(pubkey, origin);
    // Relays keep only the newest counter: never publish one without having
    // read every relay's, or a lower value could replace a higher one (#140).
    if (relays !== undefined) await writeCounter(index + 1, relays);
    const events: Event[] = [];
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

  const complete = list.synced === 'Synced' || list.synced === 'NoRelays'; // NoRelays: sync off on purpose (tests)
  // New only on evidence (#136): an empty list that didn't sync, relays that
  // didn't answer, or anything the lookup found, mean an existing account.
  const isNew =
    current.length === 0 &&
    deps.knownExisting !== true &&
    (deps.provenNew === true || (complete && counterEvents !== null && relayCounter === null));
  const listMissing = current.length === 0 && !isNew;
  const onlyIdentity0 = listMissing && relayCounter === 1;
  // A counter missing although the list knows identities (relays didn't
  // answer at creation, #136): write it now, from the synced list only.
  const listed = current.map((i) => i.index ?? 0);
  if (!isNew && complete && counterEvents !== null && relayCounter === null && listed.length > 0)
    void writeCounter(Math.max(...listed) + 1).catch(() => {});
  const pubkey0 = await pubkeyOf(0);
  const profileFree = async (pubkey: string) => {
    // The lookup already saw no event at all by identity 0.
    if (isNew && deps.provenNew === true && pubkey === pubkey0) return true;
    const found = await deps.query({ kinds: [0], authors: [pubkey], limit: 1 });
    return found !== null && found.length === 0;
  };
  // A first sign-in, or a new device that didn't sync: identity 0 exists for
  // sure (it's derived), so it's listed even without Evolu (never a second
  // account, D5).
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
    complete,
    isNew,
    listMissing,
    onlyIdentity0,
    profileFree,
    pair: async (pubkey) => {
      const i = find(pubkey);
      if (!i) throw new Error('Not an identity of this account');
      // Identity 0 on a first sign-in (or an unsynced device) isn't in Evolu yet.
      const known = (await list.load()).some((r) => r.pubkey === pubkey);
      if (!known && i.index !== null)
        await list.addDerived(i.index, pubkey, i.createdOn ?? origin, i.label);
      await list.pair(pubkey, origin);
      // A new account gets its counter event at once: a witness on relays that
      // it exists (review 8, item 4); only after reading the relays' one.
      if (isNew && counterEvents && relayCounter === null) await writeCounter(1);
      await reload();
    },
    publishProfile: async (pubkey, profile) => {
      const i = find(pubkey);
      if (!i) throw new Error('Not an identity of this account');
      // Never over an existing profile, nor when the relays can't say (#136).
      if (!(await profileFree(pubkey))) return false;
      const k = i.storedKey ? fromHexKey(i.storedKey) : await deriveIdentity(root, i.index ?? 0);
      const event = finalizeEvent(
        { kind: 0, created_at: now(), tags: [], content: JSON.stringify(profile) },
        k
      );
      k.fill(0);
      await deps.publish([event]);
      return true;
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
    primary: deps.primary ?? null,
    get links() {
      return links;
    },
    unlinkedVia: via?.unlinkedAt ?? null,
    relistedLink,
    isRoot: (rootHex) =>
      rootHex === Array.from(root, (x) => x.toString(16).padStart(2, '0')).join(''),
    link: async (login, scope, after = 0) => {
      if (!deps.primary) throw new Error('The account’s first sign-in isn’t known here');
      const { pubkey } = await pointerAddress(login.key);
      const previous = links.find((l) => l.pointerPubkey === pubkey);
      const record = await sealLink(
        root,
        login,
        await linkScope(scope),
        deps.primary,
        Math.max(previous?.version ?? 0, after) + 1,
        linkingDeps()
      );
      await list.saveLink(record);
      links = await list.links();
    },
    unlink: async (pointerPubkey) => {
      const record = links.find((l) => l.pointerPubkey === pointerPubkey && !l.unlinkedAt);
      if (!record) return;
      await list.saveLink(await unlinkRecord(record, linkingDeps()));
      links = await list.links();
    },
    exportMasterKey: (password) => exportMasterKey(root, password),
    backupFile: () =>
      buildBackupFile({
        v: 1,
        root: Array.from(root, (x) => x.toString(16).padStart(2, '0')).join(''),
        counter: Math.max(relayCounter ?? 0, listNext(current) ?? 0, 1),
        identities: current,
        links,
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
