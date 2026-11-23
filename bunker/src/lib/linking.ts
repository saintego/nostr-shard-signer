// Linking sign-ins (#73 D25, review 8; #98). What a login finds when it signs
// in (its own account, an envelope from another account, both, or nothing),
// sealing a link, unlinking from any session with the root, and re-sending the
// stored pointers. The popup's views drive these; no JSX here.

import type { Event, Filter } from 'nostr-tools';
import { getPublicKey } from 'nostr-tools/pure';
import { counterFilter, counterPubkey } from './counter';
import {
  deriveEnvelopeOwner,
  deriveIdentity,
  derivePointerD,
  derivePointerKey,
  deriveRoot,
  deriveStoreKey,
} from './derive';
import {
  buildPointer,
  type EnvelopeBody,
  type LinkedIdentity,
  newer,
  type Primary,
  pointerAddress,
  pointerFilter,
  readCopy,
  sealEnvelope,
  unlinkedContent,
} from './envelope';
import type { EnvelopeCopies } from './envelopeStore';
import type { GlobalList, LinkRecord } from './globalListModel';
import type { SiteGrant } from './siteGrant';

/** One provider login in the popup: its key and who it is (Web3Auth's user info). */
export interface Login {
  readonly key: Uint8Array;
  readonly provider: string;
  /** Web3Auth's user id for this login (to refuse linking a login to itself, review 8 item 8). */
  readonly userId: string;
  /** Masked email or handle, shown before sealing and after ("a…@gmail.com"). */
  readonly masked: string;
}

export interface LinkingDeps {
  /** Events matching a filter; null when no relay answered. */
  readonly query: (filter: Filter) => Promise<Event[] | null>;
  readonly publish: (events: Event[]) => Promise<void>;
  readonly openCopies: (ownerSecret: Uint8Array) => Promise<EnvelopeCopies>;
  readonly openList: (root: Uint8Array) => Promise<GlobalList>;
  readonly now?: () => number;
  /**
   * Background work the caller waits for later (e.g. the sign-in window before
   * it closes, #110). Without it, the Evolu copy's sync is awaited here.
   */
  readonly defer?: (work: Promise<unknown>) => void;
}

const nowS = () => Math.floor(Date.now() / 1000);

/** Closes an envelope copy after a write: its sync deferred when the caller can wait later (#110). */
const closeCopies = async (copies: EnvelopeCopies, deps: Pick<LinkingDeps, 'defer'>) => {
  const closing = copies.close();
  if (deps.defer) deps.defer(closing);
  else await closing;
};
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => Number.parseInt(x, 16));

/** What a login found when it signed in. */
export interface Found {
  /** The newest envelope copy for this login (pointer or Evolu), if any. */
  readonly envelope: EnvelopeBody | null;
  /** Evidence that this login is the primary of an account of its own (review 8, item 4). */
  readonly own: boolean;
  /** Every place answered: relays (EOSE) and Evolu synced. "Nothing found" needs this (item 5). */
  readonly answered: boolean;
  /** This login's own global list, opened (reuse it when the login is primary). */
  readonly ownList: GlobalList;
}

/**
 * Looks up a login: its envelope (pointer and Evolu copy) and evidence of its
 * own account (its global list, its counter event, events by its identity 0).
 */
export async function lookUp(loginKey: Uint8Array, deps: LinkingDeps): Promise<Found> {
  const root = await deriveRoot(loginKey);
  try {
    const address = await pointerAddress(loginKey);
    const owner = await deriveEnvelopeOwner(loginKey);
    const id0 = await deriveIdentity(root, 0);
    const pubkey0 = getPublicKey(id0);
    id0.fill(0);
    const [pointers, copies, ownList, counter, published] = await Promise.all([
      deps.query(pointerFilter(address)),
      deps.openCopies(owner),
      deps.openList(root),
      counterPubkey(root).then((pub) => deps.query(counterFilter(pub))),
      deps.query({ authors: [pubkey0], limit: 1 }),
    ]);
    owner.fill(0);
    let envelope: EnvelopeBody | null = null;
    for (const e of pointers ?? []) {
      if (e.pubkey === address.pubkey)
        envelope = newer(envelope, await readCopy(e.content, loginKey));
    }
    for (const c of await copies.contents())
      envelope = newer(envelope, await readCopy(c, loginKey));
    await copies.close(0); // only read here
    const rows = await ownList.load();
    const own = rows.length > 0 || (counter?.length ?? 0) > 0 || (published?.length ?? 0) > 0;
    const answered =
      pointers !== null &&
      counter !== null &&
      published !== null &&
      copies.synced &&
      ownList.synced === 'Synced';
    return { envelope, own, answered, ownList };
  } finally {
    root.fill(0);
  }
}

/** What the popup does with a login (#98). */
export type Resolution =
  /** The login's own account (it's a primary). */
  | { readonly kind: 'own' }
  /** An envelope opens another account's root. */
  | { readonly kind: 'linked'; readonly root: Uint8Array; readonly primary: Primary }
  /** A restricted link: only its identities. */
  | {
      readonly kind: 'restricted';
      readonly envelope: Extract<EnvelopeBody, { scope: 'restricted' }>;
    }
  /** Both: ask which (scenario 61). */
  | { readonly kind: 'both'; readonly root: Uint8Array; readonly primary: Primary }
  /** Nothing anywhere, every place answered: "No account uses this sign-in yet" (item 1). */
  | { readonly kind: 'none'; readonly wasUnlinked: boolean }
  /** Something didn't answer: "Couldn't check right now. Try again", no create button (item 5). */
  | { readonly kind: 'unknown' };

export function resolve(found: Pick<Found, 'envelope' | 'own' | 'answered'>): Resolution {
  const e = found.envelope;
  const live = e && !('unlinked' in e) ? e : null;
  if (live && live.scope === 'restricted')
    return found.own ? { kind: 'own' } : { kind: 'restricted', envelope: live };
  if (live && live.scope === 'full') {
    const root = fromHex(live.root);
    return found.own
      ? { kind: 'both', root, primary: live.primary }
      : { kind: 'linked', root, primary: live.primary };
  }
  // A login whose own account is found signs in without waiting for the pointer lookup (item 5).
  if (found.own) return { kind: 'own' };
  return found.answered ? { kind: 'none', wasUnlinked: e !== null } : { kind: 'unknown' };
}

/** Why linking a login is refused, or null if it may be linked (review 8, items 4 and 8). */
export function linkRefusal(
  current: { readonly key: Uint8Array; readonly userId: string },
  candidate: { readonly key: Uint8Array; readonly userId: string },
  found: Pick<Found, 'envelope' | 'own' | 'answered'>,
  /** This account's root (hex): an envelope already opening it is a link left half-done, linked again. */
  ownRoot?: string
): 'same-login' | 'own-account' | 'linked-elsewhere' | 'unknown' | null {
  if (
    toHex(current.key) === toHex(candidate.key) ||
    (current.userId && current.userId === candidate.userId)
  )
    return 'same-login';
  if (found.own) return 'own-account';
  const e = found.envelope;
  if (e && !('unlinked' in e) && !(ownRoot && e.scope === 'full' && e.root === ownRoot))
    return 'linked-elsewhere';
  return found.answered ? null : 'unknown';
}

/** What a new link opens: the whole account, or chosen identities (a restricted link). */
export type LinkScope =
  | { readonly kind: 'full' }
  | { readonly kind: 'restricted'; readonly identities: readonly LinkedIdentity[] };

/**
 * Seals the root (or chosen identities) for `login`, publishes the pointer,
 * writes the Evolu copy, and returns the record to keep under the root.
 */
export async function sealLink(
  root: Uint8Array,
  login: Login,
  scope: LinkScope,
  primary: Primary,
  version: number,
  deps: LinkingDeps
): Promise<LinkRecord> {
  const now = (deps.now ?? nowS)();
  const body: EnvelopeBody =
    scope.kind === 'full'
      ? { v: 1, version, scope: 'full', root: toHex(root), primary }
      : {
          v: 1,
          version,
          scope: 'restricted',
          identities: scope.identities,
          storeSecret: toHex(crypto.getRandomValues(new Uint8Array(32))),
          primary,
        };
  const sealed = await sealEnvelope(login.key, body);
  const pointerKey = await derivePointerKey(login.key);
  const d = await derivePointerD(login.key);
  const owner = await deriveEnvelopeOwner(login.key);
  try {
    const event = buildPointer(pointerKey, d, sealed, now);
    await deps.publish([event]);
    const copies = await deps.openCopies(owner);
    await copies.write(JSON.stringify(sealed));
    await closeCopies(copies, deps);
    return {
      provider: login.provider,
      masked: login.masked,
      scope: scope.kind === 'full' ? 'full' : scope.identities.map((i) => i.pubkey),
      pointerPubkey: getPublicKey(pointerKey),
      pointerKey: toHex(pointerKey),
      pointerD: d,
      envelopeOwner: toHex(owner),
      version,
      pointerEvent: JSON.stringify(event),
      linkedAt: new Date(now * 1000).toISOString(),
      unlinkedAt: null,
    };
  } finally {
    pointerKey.fill(0);
    owner.fill(0);
  }
}

/**
 * Unlinks from any session with the root (review 8, item 3): a newer plain
 * "unlinked" version in the pointer and the Evolu copy, from the stored keys.
 */
export async function unlinkRecord(link: LinkRecord, deps: LinkingDeps): Promise<LinkRecord> {
  const now = (deps.now ?? nowS)();
  const version = link.version + 1;
  const content = unlinkedContent(version);
  const pointerKey = fromHex(link.pointerKey);
  const event = buildPointer(pointerKey, link.pointerD, content, now);
  pointerKey.fill(0);
  await deps.publish([event]);
  const copies = await deps.openCopies(fromHex(link.envelopeOwner));
  await copies.write(content);
  await closeCopies(copies, deps);
  return {
    ...link,
    version,
    pointerEvent: JSON.stringify(event),
    unlinkedAt: new Date(now * 1000).toISOString(),
  };
}

/** The stored pointer events, re-sent at each global sign-in (review 8, item 9). */
export function storedPointers(links: readonly LinkRecord[]): Event[] {
  const events: Event[] = [];
  for (const l of links) {
    try {
      events.push(JSON.parse(l.pointerEvent) as Event);
    } catch {
      // unreadable: rewritten at the next change
    }
  }
  return events;
}

/** The record for a login that signs in through an envelope, if the list knows it. */
export async function linkFor(
  loginKey: Uint8Array,
  links: readonly LinkRecord[]
): Promise<LinkRecord | null> {
  const { pubkey } = await pointerAddress(loginKey);
  return links.find((l) => l.pointerPubkey === pubkey) ?? null;
}

/**
 * What a restricted sign-in hands a site (#98): the chosen identity, and a
 * per-site store of its own (from the link's store secret: the site store
 * keys come from the root, which a restricted link never has).
 */
export async function restrictedGrant(
  envelope: Extract<EnvelopeBody, { scope: 'restricted' }>,
  site: string,
  pubkey: string
): Promise<SiteGrant> {
  const chosen = envelope.identities.find((i) => i.pubkey === pubkey);
  if (!chosen) throw new Error('This sign-in doesn’t open that identity');
  const storeKey = await deriveStoreKey(fromHex(envelope.storeSecret), site);
  const grant = {
    storeKey: toHex(storeKey),
    identities: [{ secretKey: chosen.secretKey, pubkey: chosen.pubkey, label: chosen.label }],
    active: chosen.pubkey,
  };
  storeKey.fill(0);
  return grant;
}
