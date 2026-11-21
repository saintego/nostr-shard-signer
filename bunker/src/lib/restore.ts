// The /restore page's logic (#73 D10, #87): opened by the user only, it turns
// the root (from the master key or a backup file) back into the identities,
// whose keys the user then exports into another signer.

import { nsecEncode } from 'nostr-tools/nip19';
import { encrypt as nip49Encrypt } from 'nostr-tools/nip49';
import { getPublicKey } from 'nostr-tools/pure';
import { deriveIdentity } from './derive';
import type { ListedIdentity } from './globalListModel';

/** Why /restore won't run here, or null when it may. */
export function restoreRefusal(win: {
  top: unknown;
  opener: unknown;
  self: unknown;
}): string | null {
  if (win.top !== win.self) return 'framed';
  if (win.opener) return 'opened';
  return null;
}

/**
 * The identities to show: every derived index below `counter` (identities
 * exist whether or not the list knows them), with what the list knows about
 * them, then stored identities from the list.
 */
export async function restoredIdentities(
  root: Uint8Array,
  counter: number,
  list: readonly ListedIdentity[]
): Promise<ListedIdentity[]> {
  const known = new Map(list.map((i) => [i.pubkey, i]));
  const out: ListedIdentity[] = [];
  const last = Math.max(counter, ...list.map((i) => (i.index ?? -1) + 1), 1);
  for (let index = 0; index < last; index++) {
    const k = await deriveIdentity(root, index);
    const pubkey = getPublicKey(k);
    k.fill(0);
    out.push(
      known.get(pubkey) ?? {
        pubkey,
        index,
        label: null,
        createdOn: null,
        storedKey: null,
        usedElsewhere: false,
        sites: [],
      }
    );
  }
  // Stored identities (D9): brought over or imported; their keys are in the list.
  for (const i of list) if (i.index === null && i.storedKey) out.push(i);
  return out;
}

/** An identity's key to import into another signer: NIP-49 with a password, else nsec. */
export async function exportIdentity(
  root: Uint8Array,
  which: number | { readonly storedKey: string },
  password?: string
): Promise<string> {
  const k =
    typeof which === 'number'
      ? await deriveIdentity(root, which)
      : Uint8Array.from(which.storedKey.match(/../g) ?? [], (x) => Number.parseInt(x, 16));
  try {
    return password ? nip49Encrypt(k, password, 16, 0x02) : nsecEncode(k);
  } finally {
    k.fill(0);
  }
}
