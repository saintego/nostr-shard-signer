// C12: derivation test vectors (D2) in this browser's WebCrypto.

import {
    canonicalOrigin, deriveBackupKey, deriveConfigKey, deriveCounterKey, deriveIdentity,
    deriveMarkerKey, deriveRoot, deriveSettingsKey, deriveStoreKey,
} from '../lib/derive';
import { getPublicKey } from 'nostr-tools/pure';
import vectors from './vectors.json';
import { Report, fromHex, hex } from './ui';

export async function runC12(r: Report): Promise<boolean> {
    let ok = true;
    const eq = (what: string, got: string, want: string) => {
        if (got !== want) {
            ok = false;
            r.fail(`${what}: got ${got.slice(0, 16)}…, want ${want.slice(0, 16)}…`);
        }
    };
    for (const v of vectors.vectors) {
        const login = fromHex(v.globalLoginKey);
        const root = await deriveRoot(login);
        eq('root', hex(root), v.root.secret);
        eq('root pubkey', getPublicKey(root), v.root.pubkey);
        for (const id of v.identities) {
            const k = await deriveIdentity(root, id.index);
            eq(`identity ${id.index}`, hex(k), id.secret);
            eq(`identity ${id.index} pubkey`, getPublicKey(k), id.pubkey);
        }
        for (const s of v.sites) {
            eq(`canonical(${s.input})`, canonicalOrigin(s.input), s.canonical);
            eq(`marker key ${s.input}`, hex(await deriveMarkerKey(root, s.input)), s.markerKey.secret);
            eq(`store key ${s.input}`, hex(await deriveStoreKey(root, s.input)), s.storeKey);
        }
        eq('counter key', hex(await deriveCounterKey(root)), v.counterKey.secret);
        eq('config key', hex(await deriveConfigKey(root)), v.configKey.secret);
        eq('backup key', hex(await deriveBackupKey(root)), v.backupKey);
        eq('settings key', hex(await deriveSettingsKey(fromHex(v.settingsKeyFromM.m))), v.settingsKeyFromM.key);
    }
    for (const bad of ['file:///etc/passwd', 'data:text/html,x', 'not a url', 'javascript:alert(1)']) {
        try {
            canonicalOrigin(bad);
            ok = false;
            r.fail(`canonicalOrigin accepted ${bad}`);
        } catch (_) { /* refused, as it should */ }
    }
    const n = vectors.vectors.length;
    if (ok) r.pass(`All derivation vectors match (${n} login keys: root, 4 identities, 6 origin forms, counter, config, backup, settings), and non-web origins are refused`);
    return ok;
}
