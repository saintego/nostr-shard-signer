// Envelopes and pointers (#73 D25, #98): how a linked sign-in reaches the
// account. The envelope holds the root (a full link) or only chosen
// identities' keys (a restricted link), sealed with AES-GCM under a key from
// the linked login (derive.ts). Two copies: in that login's own Evolu
// database, and in a pointer event (kind 30078) signed by a key from the same
// login, at a `d` tag from it, so only that login can find and open it. An
// "unlinked" version replaces it; the newest version wins, "unlinked" a tie.

import { type Event, finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import { deriveEnvelopeKey, derivePointerD, derivePointerKey } from './derive';
import { newestFirst, signatureValid } from './marker';

export const POINTER_KIND = 30078;

/** The provider the account was created with, shown at sign-in ("created with Google, a…@gmail.com"). */
export interface Primary {
  readonly provider: string;
  readonly masked: string;
}

/** An identity a restricted link opens. */
export interface LinkedIdentity {
  readonly secretKey: string;
  readonly pubkey: string;
  readonly index: number | null;
  readonly label: string | null;
}

export type EnvelopeBody =
  | {
      readonly v: 1;
      readonly version: number;
      readonly scope: 'full';
      readonly root: string;
      readonly primary: Primary;
    }
  | {
      readonly v: 1;
      readonly version: number;
      readonly scope: 'restricted';
      readonly identities: readonly LinkedIdentity[];
      /** Random secret for the per-site stores of sites paired through this link. */
      readonly storeSecret: string;
      readonly primary: Primary;
    }
  | { readonly v: 1; readonly version: number; readonly unlinked: true };

export interface Sealed {
  readonly iv: string;
  readonly ct: string;
}

const AAD = new TextEncoder().encode('nostr-shard-signer/v1|envelope');
const toB64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const isHex64 = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);

const aesKey = async (loginKey: Uint8Array, usage: KeyUsage) => {
  const raw = await deriveEnvelopeKey(loginKey);
  try {
    return await crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, [usage]);
  } finally {
    raw.fill(0);
  }
};

/** Seals a body under the linked login's envelope key. */
export async function sealEnvelope(loginKey: Uint8Array, body: EnvelopeBody): Promise<Sealed> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(body));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: AAD },
    await aesKey(loginKey, 'encrypt'),
    plain
  );
  return { iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}

function parseBody(value: unknown): EnvelopeBody | null {
  const v = value as Record<string, unknown> | null;
  if (v?.v !== 1 || typeof v.version !== 'number' || !Number.isSafeInteger(v.version)) return null;
  if (v.unlinked === true) return { v: 1, version: v.version, unlinked: true };
  const p = v.primary as Partial<Primary> | undefined;
  if (!p || typeof p.provider !== 'string' || typeof p.masked !== 'string') return null;
  const primary = { provider: p.provider, masked: p.masked };
  if (v.scope === 'full' && isHex64(v.root))
    return { v: 1, version: v.version, scope: 'full', root: v.root, primary };
  if (v.scope === 'restricted' && isHex64(v.storeSecret) && Array.isArray(v.identities)) {
    const identities = (v.identities as Partial<LinkedIdentity>[]).filter(
      (i): i is LinkedIdentity => isHex64(i?.secretKey) && isHex64(i?.pubkey)
    );
    if (identities.length !== v.identities.length || identities.length === 0) return null;
    return {
      v: 1,
      version: v.version,
      scope: 'restricted',
      identities,
      storeSecret: v.storeSecret,
      primary,
    };
  }
  return null;
}

/** Opens a sealed envelope with the linked login; null if it's not this login's, or malformed. */
export async function openEnvelope(
  loginKey: Uint8Array,
  sealed: Sealed
): Promise<EnvelopeBody | null> {
  try {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(sealed.iv) as BufferSource, additionalData: AAD },
      await aesKey(loginKey, 'decrypt'),
      fromB64(sealed.ct) as BufferSource
    );
    return parseBody(JSON.parse(new TextDecoder().decode(plain)));
  } catch {
    return null;
  }
}

/** The newest of two versions; "unlinked" wins a tie (#98). */
export function newer(a: EnvelopeBody | null, b: EnvelopeBody | null): EnvelopeBody | null {
  if (!a) return b;
  if (!b) return a;
  if (a.version !== b.version) return a.version > b.version ? a : b;
  return 'unlinked' in b ? b : a;
}

/** Where the pointer lives: its author and `d` tag, from the linked login. */
export async function pointerAddress(loginKey: Uint8Array): Promise<{ pubkey: string; d: string }> {
  const k = await derivePointerKey(loginKey);
  try {
    return { pubkey: getPublicKey(k), d: await derivePointerD(loginKey) };
  } finally {
    k.fill(0);
  }
}

export const pointerFilter = (address: { pubkey: string; d: string }) => ({
  kinds: [POINTER_KIND],
  authors: [address.pubkey],
  '#d': [address.d],
});

/**
 * The "unlinked" version in plain form: unlinking happens from any session with
 * the root (#98), which holds the pointer key and the envelope's owner but not
 * the linked login's envelope key. The pointer's signature says who wrote it;
 * the content only says "unlinked" and its version.
 */
export const unlinkedContent = (version: number) =>
  JSON.stringify({ v: 1, version, unlinked: true });

/**
 * A pointer event: a sealed envelope, or the plain "unlinked" version.
 * `pointerKey` comes from the linked login (derivePointerKey) or from the
 * global list, which keeps it for unlinking.
 */
export function buildPointer(
  pointerKey: Uint8Array,
  d: string,
  content: Sealed | string,
  now: number
): Event {
  const text = typeof content === 'string' ? content : JSON.stringify(content);
  return finalizeEvent(
    { kind: POINTER_KIND, created_at: now, tags: [['d', d]], content: text },
    pointerKey
  );
}

/** A stored copy (pointer content or Evolu row): sealed, or the plain "unlinked" version. */
export async function readCopy(
  content: string,
  loginKey: Uint8Array
): Promise<EnvelopeBody | null> {
  try {
    const s = JSON.parse(content) as Partial<Sealed> & {
      unlinked?: unknown;
      version?: unknown;
      v?: unknown;
    };
    if (s.unlinked === true) return parseBody(s);
    if (typeof s.iv === 'string' && typeof s.ct === 'string')
      return openEnvelope(loginKey, { iv: s.iv, ct: s.ct });
  } catch {
    // not ours
  }
  return null;
}

/** The newest readable envelope among pointer events from this login's pointer key. */
export async function readPointer(
  events: readonly Event[],
  loginKey: Uint8Array
): Promise<EnvelopeBody | null> {
  const address = await pointerAddress(loginKey);
  const mine = events
    .filter((e) => e.kind === POINTER_KIND && e.pubkey === address.pubkey)
    .filter((e) => e.tags.some((t) => t[0] === 'd' && t[1] === address.d))
    .filter(signatureValid)
    .sort(newestFirst);
  let best: EnvelopeBody | null = null;
  for (const e of mine) best = newer(best, await readCopy(e.content, loginKey));
  return best;
}

/** "a…@gmail.com", "@a…", or the first character: enough to recognise, not to identify. */
export function maskIdentifier(id: string): string {
  const at = id.indexOf('@');
  if (at > 0) return `${id[0]}…${id.slice(at)}`;
  if (id.startsWith('@')) return `@${id[1] ?? ''}…`;
  return id ? `${id[0]}…` : '';
}
