// The encrypted backup file (#73 D10, #87). The body (the root, the counter,
// the identities with labels, where they were created and are used) is
// encrypted with a random AES-GCM file key; only that 32-byte key is NIP-44
// encrypted to the root, from a one-time key, so it fits NIP-44's size limit
// however large the body grows. Anyone holding the root opens it: the master
// key typed in at /restore, or Amber or an extension that holds the root.

import * as nip44 from 'nostr-tools/nip44';
import { getPublicKey } from 'nostr-tools/pure';
import type { ListedIdentity } from './globalListModel';
import type { Result } from './masterKey';

export const BACKUP_TYPE = 'nostr-shard-signer-backup';

export interface BackupBody {
  readonly v: 1;
  /** Hex root. */
  readonly root: string;
  /** The next unused derivation index (D12). */
  readonly counter: number;
  readonly identities: readonly ListedIdentity[];
  /** ISO date. */
  readonly createdAt: string;
}

/** The file as saved (JSON). Nothing in it is readable without the root. */
export interface BackupFile {
  readonly type: typeof BACKUP_TYPE;
  readonly v: 1;
  /** The root's pubkey: which key opens it (an extension can be checked against it). */
  readonly rootPubkey: string;
  /** The one-time key the file key was encrypted from. */
  readonly senderPubkey: string;
  /** The file key, NIP-44 encrypted to the root. */
  readonly fileKey: string;
  readonly iv: string;
  readonly body: string;
}

/** Decrypts the file key: NIP-44 from `senderPubkey`, with the root (or a signer holding it). */
export type FileKeyDecrypter = (senderPubkey: string, ciphertext: string) => Promise<string>;

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => Number.parseInt(x, 16));
const toB64 = (b: Uint8Array) => {
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
};
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

const aesKey = (raw: Uint8Array, usage: KeyUsage) =>
  crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, [usage]);

/** The backup file (JSON text) for `body`, which holds the root. */
export async function buildBackupFile(body: BackupBody): Promise<string> {
  const root = fromHex(body.root);
  const fileKey = crypto.getRandomValues(new Uint8Array(32));
  const sender = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  try {
    const plain = new TextEncoder().encode(JSON.stringify(body));
    const cipher = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(fileKey, 'encrypt'), plain)
    );
    const rootPubkey = getPublicKey(root);
    const file: BackupFile = {
      type: BACKUP_TYPE,
      v: 1,
      rootPubkey,
      senderPubkey: getPublicKey(sender),
      fileKey: nip44.encrypt(toHex(fileKey), nip44.getConversationKey(sender, rootPubkey)),
      iv: toB64(iv),
      body: toB64(cipher),
    };
    return JSON.stringify(file);
  } finally {
    root.fill(0);
    fileKey.fill(0);
    sender.fill(0);
  }
}

/** Reads the outer file (no key needed): which root opens it. */
export function parseBackupFile(text: string): Result<BackupFile> {
  try {
    const f = JSON.parse(text) as Partial<BackupFile>;
    const hex64 = (s: unknown) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
    if (f.type !== BACKUP_TYPE || f.v !== 1 || !hex64(f.rootPubkey) || !hex64(f.senderPubkey))
      return { ok: false, error: 'This isn’t a backup file from this signer.' };
    if (typeof f.fileKey !== 'string' || typeof f.iv !== 'string' || typeof f.body !== 'string')
      return { ok: false, error: 'This backup file is damaged.' };
    return { ok: true, value: f as BackupFile };
  } catch {
    return { ok: false, error: 'This isn’t a backup file from this signer.' };
  }
}

/** The decrypter for someone holding the root itself (the master key). */
export const withRoot =
  (root: Uint8Array): FileKeyDecrypter =>
  async (senderPubkey, ciphertext) =>
    nip44.decrypt(ciphertext, nip44.getConversationKey(root, senderPubkey));

/** Opens the file: the file key through `decrypt`, then the body. */
export async function openBackupFile(
  file: BackupFile,
  decrypt: FileKeyDecrypter
): Promise<Result<BackupBody>> {
  let fileKey: Uint8Array;
  try {
    const hex = await decrypt(file.senderPubkey, file.fileKey);
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('bad key');
    fileKey = fromHex(hex);
  } catch {
    return { ok: false, error: 'This key doesn’t open this backup file.' };
  }
  try {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(file.iv) as BufferSource },
      await aesKey(fileKey, 'decrypt'),
      fromB64(file.body) as BufferSource
    );
    const body = JSON.parse(new TextDecoder().decode(plain)) as BackupBody;
    if (
      body.v !== 1 ||
      !/^[0-9a-f]{64}$/.test(body.root) ||
      getPublicKey(fromHex(body.root)) !== file.rootPubkey
    )
      return { ok: false, error: 'This backup file is damaged.' };
    return { ok: true, value: body };
  } catch {
    return { ok: false, error: 'This backup file is damaged.' };
  } finally {
    fileKey.fill(0);
  }
}
