// The master key (#73 D10, #87): the root, written down by the user as their
// last-resort backup. Exported only in the signer's popup; typed back in only
// at <signer origin>/restore (restore.html), never in a widget.

import { decode, nsecEncode } from 'nostr-tools/nip19';
import { decrypt as nip49Decrypt, encrypt as nip49Encrypt } from 'nostr-tools/nip49';

export type Result<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: string };

const ok = <T>(value: T): Result<T> => ({ ok: true, value });
const fail = <T>(error: string): Result<T> => ({ ok: false, error });

/** Where restoring happens: `<signer base>/restore/`, opened by the user only. */
export const restoreUrl = (signerBase: string) => new URL('restore/', signerBase).href;

/**
 * The master key as text: NIP-49 (`ncryptsec`, password-protected; scrypt
 * log2(N) = 16) when a password is given, else a plain `nsec`. Open question 2
 * of #73: both are offered, the password one first.
 */
export function exportMasterKey(root: Uint8Array, password?: string): string {
  return password ? nip49Encrypt(root, password, 16, 0x02) : nsecEncode(root);
}

const HEX64 = /^[0-9a-f]{64}$/;

/** Is this an `ncryptsec` (then a password is needed)? */
export const needsPassword = (input: string) => input.trim().startsWith('ncryptsec1');

/** The root from what the user typed: nsec, ncryptsec (+ password) or 64 hex. */
export function parseMasterKey(input: string, password = ''): Result<Uint8Array> {
  const text = input.trim();
  if (HEX64.test(text))
    return ok(Uint8Array.from(text.match(/../g) ?? [], (h) => Number.parseInt(h, 16)));
  if (needsPassword(text)) {
    if (!password) return fail('This master key is protected: enter its password.');
    try {
      return ok(nip49Decrypt(text, password));
    } catch {
      return fail('Wrong password, or the master key was mistyped.');
    }
  }
  try {
    const d = decode(text);
    if (d.type === 'nsec') return ok(d.data);
  } catch {
    // fall through
  }
  return fail('That isn’t a master key: it starts with nsec1 or ncryptsec1.');
}
