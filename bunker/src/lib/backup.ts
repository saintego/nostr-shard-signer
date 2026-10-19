import { SimplePool, finalizeEvent } from "nostr-tools";
import * as nip44 from "nostr-tools/nip44";
import { encrypt as nip49Encrypt } from "nostr-tools/nip49";
import { publishToRelay } from "./nostr";

// Asking OAuth users to back up their key (#37). Whether they did is kept on
// Nostr, so a backup made on one site or device counts everywhere: the signer's
// own storage is per site in browsers that partition third-party storage.

export type BackupMethod = "ncryptsec" | "nsec";

// NIP-78 app-specific data, encrypted to the user themselves (NIP-44).
const MARKER_KIND = 30078;
const MARKER_D_TAG = "nostr-shard-signer/backup";

// Ask after this many signed events, and again this long after "Later".
const NUDGE_AFTER_SIGNED = 5;
const SNOOZE_MS = 14 * 24 * 60 * 60 * 1000;

const storageKey = (what: string, pubkeyHex: string) => `nostr_signer_backup_${what}_${pubkeyHex}`;

function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch (_) {
    return null;
  }
}

function write(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch (_) {
    // Storage blocked: the prompt may show again, which is harmless.
  }
}

export function isBackedUpLocally(pubkeyHex: string): boolean {
  return read(storageKey("done", pubkeyHex)) !== null;
}

function markBackedUpLocally(pubkeyHex: string, method: BackupMethod): void {
  write(storageKey("done", pubkeyHex), method);
}

/** Counts a signed event; returns the new total. */
export function countSignedEvent(pubkeyHex: string): number {
  const n = Number(read(storageKey("signed", pubkeyHex)) ?? "0") + 1;
  write(storageKey("signed", pubkeyHex), String(n));
  return n;
}

export function snoozeBackupPrompt(pubkeyHex: string): void {
  write(storageKey("snooze", pubkeyHex), String(Date.now() + SNOOZE_MS));
}

export function shouldAskForBackup(pubkeyHex: string): boolean {
  if (isBackedUpLocally(pubkeyHex)) return false;
  if (Number(read(storageKey("signed", pubkeyHex)) ?? "0") < NUDGE_AFTER_SIGNED) return false;
  return Date.now() >= Number(read(storageKey("snooze", pubkeyHex)) ?? "0");
}

/** NIP-49 ncryptsec: the key encrypted with the user's password. */
export function encryptKeyBackup(privateKeyBytes: Uint8Array, password: string): string {
  return nip49Encrypt(privateKeyBytes, password);
}

/** Remembers the backup locally and publishes the marker; relay failures are ignored. */
export async function recordBackup(
  privateKeyBytes: Uint8Array,
  pubkeyHex: string,
  method: BackupMethod,
  relays: string[],
): Promise<void> {
  markBackedUpLocally(pubkeyHex, method);
  const conversationKey = nip44.getConversationKey(privateKeyBytes, pubkeyHex);
  const event = finalizeEvent(
    {
      kind: MARKER_KIND,
      created_at: Math.floor(Date.now() / 1000),
      tags: [["d", MARKER_D_TAG]],
      content: nip44.encrypt(JSON.stringify({ backedUpAt: Date.now(), method }), conversationKey),
    },
    privateKeyBytes,
  );
  try {
    await Promise.any(relays.map((r) => publishToRelay(r, event)));
  } catch (_) {
    // Kept locally; another site may ask once more.
  }
}

/** Looks for a backup marker on relays and caches a positive answer locally. */
export async function syncBackupMarker(
  privateKeyBytes: Uint8Array,
  pubkeyHex: string,
  relays: string[],
): Promise<boolean> {
  if (isBackedUpLocally(pubkeyHex)) return true;
  const pool = new SimplePool();
  try {
    const events = await pool.querySync(
      relays,
      { authors: [pubkeyHex], kinds: [MARKER_KIND], "#d": [MARKER_D_TAG], limit: 1 },
      { maxWait: 5000 },
    );
    if (!events.length) return false;
    const conversationKey = nip44.getConversationKey(privateKeyBytes, pubkeyHex);
    const { method } = JSON.parse(nip44.decrypt(events[0].content, conversationKey)) as { method?: BackupMethod };
    markBackedUpLocally(pubkeyHex, method === "nsec" ? "nsec" : "ncryptsec");
    return true;
  } catch (_) {
    return false;
  } finally {
    pool.close(relays);
  }
}
