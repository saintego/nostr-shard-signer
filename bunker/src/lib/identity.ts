// Shared sign-in identities (#73 D1, D2; #78). On the shared project the
// Web3Auth key is the *global login key*: it is never an identity, never
// exported, never reachable through window.nostr. Identities are derived from
// it through the root (derive.ts), so the login alone always gets them back,
// and a later version can add more identities without new logins.

import { getPublicKey } from 'nostr-tools/pure';
import { nsecEncode, npubEncode } from 'nostr-tools/nip19';
import { deriveIdentity, deriveRoot } from './derive';
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
