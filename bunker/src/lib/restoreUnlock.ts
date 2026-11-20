// Opening the root at /restore (#73 D10, #87): from the master key typed in,
// or a backup file whose file key is decrypted by the master key, by the
// Nostr extension in this browser, or by Amber or another bunker (NIP-46)
// connected on this page. Never through a site's bridge.

import { type BackupFile, type FileKeyDecrypter, openBackupFile, withRoot } from './backupFile';
import { counterFilter, counterPubkey, readCounter } from './counter';
import type { ListedIdentity } from './globalListModel';
import type { Result } from './masterKey';
import { queryRelays } from './relayPublish';
import { restoredIdentities } from './restore';

/** What /restore works with once unlocked. */
export interface Unlocked {
  readonly root: Uint8Array;
  readonly identities: readonly ListedIdentity[];
  /** A signer held the root to open the file: tell the user to remove it there. */
  readonly signerHeldRoot: boolean;
}

interface Nip07 {
  getPublicKey(): Promise<string>;
  nip44?: { decrypt(pubkey: string, ciphertext: string): Promise<string> };
}

/** The NIP-07 extension in this page, if any. */
export const extension = (): Nip07 | null => (globalThis as { nostr?: Nip07 }).nostr ?? null;

/** A decrypter backed by the extension, after checking it holds the file's root. */
export async function extensionDecrypter(file: BackupFile): Promise<Result<FileKeyDecrypter>> {
  const ext = extension();
  if (!ext?.nip44)
    return { ok: false, error: 'No Nostr extension with NIP-44 was found in this browser.' };
  const pubkey = await ext.getPublicKey().catch(() => '');
  if (pubkey !== file.rootPubkey)
    return { ok: false, error: 'The extension holds another key, not this account’s master key.' };
  const nip44 = ext.nip44;
  return { ok: true, value: (sender, ct) => nip44.decrypt(sender, ct) };
}

/** A decrypter backed by a bunker (Amber…) from its bunker:// address; `close` ends the session. */
export async function bunkerDecrypter(
  file: BackupFile,
  address: string
): Promise<Result<{ decrypt: FileKeyDecrypter; close: () => Promise<void> }>> {
  const { BunkerSigner, parseBunkerInput } = await import('nostr-tools/nip46');
  const pointer = await parseBunkerInput(address.trim()).catch(() => null);
  if (!pointer) return { ok: false, error: 'That isn’t a bunker:// address.' };
  const signer = BunkerSigner.fromBunker(crypto.getRandomValues(new Uint8Array(32)), pointer);
  try {
    await signer.connect();
    if ((await signer.getPublicKey()) !== file.rootPubkey) {
      await signer.close();
      return { ok: false, error: 'The bunker holds another key, not this account’s master key.' };
    }
  } catch (e) {
    await signer.close().catch(() => {});
    return { ok: false, error: `The bunker didn’t answer: ${(e as Error)?.message ?? e}` };
  }
  return {
    ok: true,
    value: {
      decrypt: (sender, ct) => signer.nip44Decrypt(sender, ct),
      close: () => signer.close(),
    },
  };
}

const fromHex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => Number.parseInt(x, 16));

/** Unlocks a backup file with any decrypter. */
export async function unlockFile(
  file: BackupFile,
  decrypt: FileKeyDecrypter,
  signerHeldRoot: boolean
): Promise<Result<Unlocked>> {
  const body = await openBackupFile(file, decrypt);
  if (!body.ok) return body;
  const root = fromHex(body.value.root);
  const identities = await restoredIdentities(root, body.value.counter, body.value.identities);
  return { ok: true, value: { root, identities, signerHeldRoot } };
}

/** Unlocks a backup file with the master key itself. */
export const unlockFileWithRoot = (file: BackupFile, root: Uint8Array) =>
  unlockFile(file, withRoot(root), false);

/**
 * The master key alone: identities below the counter on relays and in the
 * global list (Evolu), or at least identity 0.
 */
export async function unlockWithRoot(
  root: Uint8Array,
  list: readonly ListedIdentity[]
): Promise<Unlocked> {
  const events = await queryRelays(counterFilter(await counterPubkey(root)));
  const counter = (events ? await readCounter(events, root) : null) ?? 1;
  return { root, identities: await restoredIdentities(root, counter, list), signerHeldRoot: false };
}
