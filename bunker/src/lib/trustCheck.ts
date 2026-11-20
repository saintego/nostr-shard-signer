// Applies the trust rule (trustRule.ts) to a request (#85): fetches the event
// now at the address, reads this site's records, compares private list
// entries, and records what this site signed. Records live in the iframe's
// storage, which is this site's own (partitioned); they move to the site's
// Evolu store with #81.

import { SimplePool } from 'nostr-tools';
import * as nip04 from 'nostr-tools/nip04';
import * as nip44 from 'nostr-tools/nip44';
import { isProtectedEvent } from '../vendor/evolustr/evolustr.js';
import { requiresConfirmation } from './approval';
import {
  addedEntries,
  type CurrentEvent,
  entryKey,
  isAddressable,
  isList,
  isReplaceable,
  type SignRequest,
  type RefuseReason,
  type TrustDecision,
  trustDecision,
} from './trustRule';

const QUERY_TIMEOUT_MS = 4000;
const MEDIA_UPLOAD_HOSTS = ['nostr.build'];

interface Records {
  lastSigned: Record<string, string>;
  added: Record<string, string[]>;
  trusted?: boolean;
}

const recordsKey = (pubkey: string) => `nss_trust:${pubkey}`;

function loadRecords(pubkey: string): Records {
  try {
    const v = JSON.parse(localStorage.getItem(recordsKey(pubkey)) ?? 'null') as Records | null;
    if (v && typeof v.lastSigned === 'object' && typeof v.added === 'object') return v;
  } catch {
    // unreadable or blocked: no records
  }
  return { lastSigned: {}, added: {} };
}

function saveRecords(pubkey: string, records: Records): void {
  try {
    localStorage.setItem(recordsKey(pubkey), JSON.stringify(records));
  } catch {
    // storage blocked: the next change asks again
  }
}

const dTag = (tags: readonly (readonly string[])[]) => tags.find((t) => t[0] === 'd')?.[1] ?? '';

/** The address of a replaceable or addressable event (NIP-01). */
export const addressOf = (evt: { kind: number; tags: readonly (readonly string[])[] }, pubkey: string) =>
  isAddressable(evt.kind) ? `${evt.kind}:${pubkey}:${dTag(evt.tags)}` : `${evt.kind}:${pubkey}:`;

const withTimeout = <T>(p: Promise<T>) =>
  Promise.race([p, new Promise<T>((_, reject) => setTimeout(() => reject(new Error('timeout')), QUERY_TIMEOUT_MS))]);

/** Where the identity publishes (its NIP-65 write relays), plus the signer's. */
async function relaysFor(pool: SimplePool, pubkey: string, base: string[]): Promise<string[]> {
  try {
    const list = await withTimeout(pool.querySync(base, { kinds: [10002], authors: [pubkey], limit: 1 }));
    const newest = list.sort((a, b) => b.created_at - a.created_at)[0];
    const write = (newest?.tags ?? []).filter((t) => t[0] === 'r' && t[2] !== 'read').map((t) => t[1] ?? '');
    return [...new Set([...base, ...write.filter((u) => u.startsWith('wss://'))])];
  } catch {
    return base;
  }
}

/** The newest event at the address; null if none; undefined if the relays didn't answer. */
async function currentAt(evt: SignRequest, pubkey: string, relays: string[]): Promise<CurrentEvent | null | undefined> {
  const pool = new SimplePool();
  try {
    const all = await relaysFor(pool, pubkey, relays);
    const filter = isAddressable(evt.kind)
      ? { kinds: [evt.kind], authors: [pubkey], '#d': [dTag(evt.tags)] }
      : { kinds: [evt.kind], authors: [pubkey] };
    const events = await withTimeout(pool.querySync(all, filter));
    const newest = events.sort((a, b) => b.created_at - a.created_at)[0];
    return newest ? { id: newest.id, tags: newest.tags, content: newest.content } : null;
  } catch {
    return undefined;
  } finally {
    pool.destroy();
  }
}

/** A list's private entries (NIP-51: tags encrypted to oneself), or null if unreadable. */
function privateEntries(content: string, secretKey: Uint8Array, pubkey: string): string[] | null {
  if (!content) return [];
  try {
    const plain = content.includes('?iv=')
      ? nip04.decrypt(secretKey, pubkey, content)
      : nip44.decrypt(content, nip44.getConversationKey(secretKey, pubkey));
    const tags = JSON.parse(plain) as unknown;
    return Array.isArray(tags) ? tags.filter(Array.isArray).map((t) => entryKey(t as string[])) : null;
  } catch {
    return null;
  }
}

function isAllowedUpload(tags: readonly (readonly string[])[]): boolean {
  const u = tags.find((t) => t[0] === 'u')?.[1];
  try {
    const url = new URL(u ?? '');
    return url.protocol === 'https:' && MEDIA_UPLOAD_HOSTS.some((h) => url.hostname === h || url.hostname.endsWith(`.${h}`));
  } catch {
    return false;
  }
}

/** The error the page gets for a refused request (to the app, not the user). */
export const refusalMessage = (reason: RefuseReason) =>
  reason === 'future'
    ? 'Refused: the event is dated in the future'
    : 'Refused: the signer never deletes its own records or vaults for a site';

export interface Decision {
  readonly decision: TrustDecision;
  /** Call with the signed event (JSON) once it was signed, silently or after a prompt. */
  readonly record?: (signedJson: string) => void;
}

export interface DecideDeps {
  readonly autoApproveKinds: Set<number>;
  readonly pubkey: string;
  readonly secretKey: Uint8Array;
  readonly relays: string[];
  /** The identity was exported, brought over or imported (D9). */
  readonly usedElsewhere?: boolean;
}

function parseRequest(params: string[]): SignRequest | null {
  try {
    const raw = JSON.parse(params[0] ?? '') as Partial<SignRequest>;
    const tags = Array.isArray(raw.tags) ? raw.tags : [];
    return { kind: Number(raw.kind), created_at: Number(raw.created_at), tags, content: String(raw.content ?? '') };
  } catch {
    return null;
  }
}

/** Private entries before and after, for lists that have any; null if unreadable. */
function privateChange(evt: SignRequest, current: CurrentEvent | null | undefined, deps: DecideDeps) {
  if (!isList(evt.kind) || !(current?.content || evt.content)) return undefined;
  const before = current?.content ? privateEntries(current.content, deps.secretKey, deps.pubkey) : [];
  const after = evt.content ? privateEntries(evt.content, deps.secretKey, deps.pubkey) : [];
  return before && after ? { before, after } : null;
}

/** Remembers what this site signed at the address, and which entries it added. */
function recorder(deps: DecideDeps, address: string, current: CurrentEvent | null | undefined, evt: SignRequest, priv: ReturnType<typeof privateChange>) {
  return (signedJson: string) => {
    try {
      const signed = JSON.parse(signedJson) as { id: string };
      const next = loadRecords(deps.pubkey);
      next.lastSigned[address] = signed.id;
      // Only entries that weren't there before count as added by this site (#73 D13).
      const added = new Set(next.added[address] ?? []);
      for (const e of addedEntries(current, evt)) added.add(e);
      for (const e of priv ? priv.after.filter((x) => !priv.before.includes(x)) : []) added.add(e);
      next.added[address] = [...added];
      saveRecords(deps.pubkey, next);
    } catch {
      // not a signed event: nothing to record
    }
  };
}

/** Whether a request may run without asking, must ask, or is refused. */
export async function decideRequest(method: string, params: string[], deps: DecideDeps): Promise<Decision> {
  if (method !== 'sign_event') {
    const ask = requiresConfirmation(method, params, deps.autoApproveKinds);
    return { decision: ask ? { action: 'ask', reason: 'always' } : { action: 'sign' } };
  }
  const evt = parseRequest(params);
  if (!evt) return { decision: { action: 'ask', reason: 'always' } };
  const replaceable = isReplaceable(evt.kind) || isAddressable(evt.kind);
  const records = loadRecords(deps.pubkey);
  const address = addressOf(evt, deps.pubkey);
  const current = replaceable && deps.autoApproveKinds.has(evt.kind) ? await currentAt(evt, deps.pubkey, deps.relays) : null;
  const priv = privateChange(evt, current, deps);
  const decision = trustDecision(evt, {
    pubkey: deps.pubkey,
    isProtectedD: (d) => isProtectedEvent({ kind: 30078, tags: [['d', d]] }),
    autoApproveKinds: deps.autoApproveKinds,
    isProtected: isProtectedEvent({ kind: evt.kind, tags: evt.tags as string[][] }),
    isAllowedUpload: isAllowedUpload(evt.tags),
    usedElsewhere: deps.usedElsewhere ?? false,
    trusted: records.trusted === true,
    current,
    lastSignedId: records.lastSigned[address],
    addedBySite: new Set(records.added[address] ?? []),
    privateEntries: priv,
    now: Math.floor(Date.now() / 1000),
  });
  return replaceable ? { decision, record: recorder(deps, address, current, evt, priv) } : { decision };
}
