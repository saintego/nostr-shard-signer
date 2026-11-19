// Shared sign-in identities (#73 D1, D2; #78). On the shared project the
// Web3Auth key is the *global login key*: it is never an identity, never
// exported, never reachable through window.nostr. Identities are derived from
// it through the root (derive.ts), so the login alone always gets them back,
// and a later version can add more identities without new logins.

import { getPublicKey } from 'nostr-tools/pure';
import { nsecEncode, npubEncode } from 'nostr-tools/nip19';
import { deriveIdentity, deriveRoot, deriveStoreKey } from './derive';
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

/** What the global sign-in gives one site (#80): its store key and identity. */
export interface SiteGrant {
  readonly storeKey: string;
  readonly identity: { readonly secretKey: string; readonly pubkey: string };
}

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/**
 * From the global login key: the site's store key and identity `index` (0
 * until #84 lists more). The login key and the root are wiped.
 */
export async function grantForSite(loginKey: Uint8Array, site: string, index = 0): Promise<SiteGrant> {
  const root = await deriveRoot(loginKey);
  loginKey.fill(0);
  try {
    const identity = await deriveIdentity(root, index);
    const storeKey = await deriveStoreKey(root, site);
    const grant = {
      storeKey: toHex(storeKey),
      identity: { secretKey: toHex(identity), pubkey: getPublicKey(identity) },
    };
    identity.fill(0);
    storeKey.fill(0);
    return grant;
  } finally {
    root.fill(0);
  }
}

/** Key material for a hex secret key (an identity from a grant or a cache). */
export function keyMaterialFromSecret(secretHex: string): KeyMaterial {
  const privateKeyBytes = new Uint8Array((secretHex.match(/../g) ?? []).map((h) => Number.parseInt(h, 16)));
  const publicKeyHex = getPublicKey(privateKeyBytes);
  return { privateKeyBytes, publicKeyHex, nsecStr: nsecEncode(privateKeyBytes), npubStr: npubEncode(publicKeyHex) };
}
