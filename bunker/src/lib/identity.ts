// Shared sign-in identities (#73 D1, D2; #78). On the shared project the
// Web3Auth key is the *global login key*: it is never an identity, never
// exported, never reachable through window.nostr. Identities are derived from
// it through the root (derive.ts), so the login alone always gets them back,
// and a later version can add more identities without new logins.

import { npubEncode, nsecEncode } from 'nostr-tools/nip19';
import { getPublicKey } from 'nostr-tools/pure';
import { deriveIdentity, deriveRoot, deriveStoreKey } from './derive';
import type { SiteGrant } from './siteGrant';
import type { KeyMaterial } from './web3auth';

/**
 * Identity `index` (0 for now) of the global account behind `login`, the key
 * Web3Auth gave for the shared project. The login key's bytes are wiped: the
 * caller must not use `login` afterwards. The root isn't kept either (v1 keeps
 * it only while a global sign-in needs it, #80).
 */
export async function sharedIdentity(login: KeyMaterial, index = 0): Promise<KeyMaterial> {
  const root = await deriveRoot(login.privateKeyBytes);
  login.privateKeyBytes.fill(0);
  try {
    const privateKeyBytes = await deriveIdentity(root, index);
    const publicKeyHex = getPublicKey(privateKeyBytes);
    return {
      privateKeyBytes,
      publicKeyHex,
      nsecStr: nsecEncode(privateKeyBytes),
      npubStr: npubEncode(publicKeyHex),
    };
  } finally {
    root.fill(0);
  }
}

/** An identity to hand a site: derived (by index) and its label. */
/** An identity to hand a site: derived (by index) or stored (D9: its key), and its label. */
export type ChosenIdentity = (
  | { readonly index: number; readonly label: string | null }
  | { readonly storedKey: string; readonly label: string | null }
) & { readonly usedElsewhere?: boolean };

const hexToBytes = (h: string) =>
  Uint8Array.from(h.match(/../g) ?? [], (x) => Number.parseInt(x, 16));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/**
 * What one site gets (#80, #84): its store key and the chosen identities'
 * keys, `active` first unless named. The root is the caller's (the popup's),
 * not wiped here.
 */
/** The grant's "used elsewhere" flag, only when set (D13). */
const elsewhere = (c: ChosenIdentity) => (c.usedElsewhere ? { usedElsewhere: true as const } : {});

export async function grantFromRoot(
  root: Uint8Array,
  site: string,
  identities: readonly ChosenIdentity[],
  activePubkey?: string
): Promise<SiteGrant> {
  if (identities.length === 0) throw new Error('No identity for this site');
  const granted = [];
  for (const chosen of identities) {
    if ('storedKey' in chosen) {
      const pubkey = getPublicKey(hexToBytes(chosen.storedKey));
      granted.push({
        secretKey: chosen.storedKey,
        pubkey,
        label: chosen.label,
        ...elsewhere(chosen),
      });
      continue;
    }
    const key = await deriveIdentity(root, chosen.index);
    granted.push({
      secretKey: toHex(key),
      pubkey: getPublicKey(key),
      label: chosen.label,
      ...elsewhere(chosen),
    });
    key.fill(0);
  }
  const storeKey = await deriveStoreKey(root, site);
  const grant = {
    storeKey: toHex(storeKey),
    identities: granted,
    active: activePubkey ?? (granted[0]?.pubkey as string),
  };
  storeKey.fill(0);
  if (!granted.some((g) => g.pubkey === grant.active))
    throw new Error('The active identity is not among them');
  return grant;
}

/** Identity 0 only (a first sign-in): the login key and the root are wiped. */
export async function grantForSite(
  loginKey: Uint8Array,
  site: string,
  index = 0
): Promise<SiteGrant> {
  const root = await deriveRoot(loginKey);
  loginKey.fill(0);
  try {
    return await grantFromRoot(root, site, [{ index, label: null }]);
  } finally {
    root.fill(0);
  }
}

/** Key material for a hex secret key (an identity from a grant or a cache). */
export function keyMaterialFromSecret(secretHex: string): KeyMaterial {
  const privateKeyBytes = new Uint8Array(
    (secretHex.match(/../g) ?? []).map((h) => Number.parseInt(h, 16))
  );
  const publicKeyHex = getPublicKey(privateKeyBytes);
  return {
    privateKeyBytes,
    publicKeyHex,
    nsecStr: nsecEncode(privateKeyBytes),
    npubStr: npubEncode(publicKeyHex),
  };
}
