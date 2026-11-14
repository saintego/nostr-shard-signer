// The shared sign-in block list signed with the registry root key (#65), so
// the operator can block a site without a deploy. A kind-30078 event by the
// root key; its d-tag contains ":", which the registrar never accepts in a
// clientId, so no registered entry can replace it. Content:
// { "origins": ["https://evil.example", "*.bad.example"] }.
// Published with scripts/publish-blocklist.mjs.

import { SimplePool } from 'nostr-tools';

export const BLOCKLIST_D_TAG = 'nostr-shard-signer:shared-blocked';

/**
 * The newest signed block list across the relays (a relay can withhold it but
 * not forge it). Resolves with [] when there is none, or after `maxWait`.
 */
export function fetchSharedBlocklist(rootPubkeyHex: string, relays: string[], maxWait = 3000): Promise<string[]> {
    return new Promise(resolve => {
        const pool = new SimplePool();
        let newest: { created_at: number; origins: string[] } | null = null;
        let done = false;
        const finish = () => {
            if (done) return;
            done = true;
            clearTimeout(safety);
            try { pool.close(relays); } catch (_) { }
            resolve(newest?.origins ?? []);
        };
        const safety = setTimeout(finish, maxWait + 500);
        try {
            pool.subscribeEose(
                relays,
                { authors: [rootPubkeyHex], kinds: [30078], '#d': [BLOCKLIST_D_TAG], limit: 1 },
                {
                    maxWait,
                    onevent: e => {
                        if (e.pubkey !== rootPubkeyHex) return;
                        if (newest && newest.created_at >= e.created_at) return;
                        try {
                            const content = JSON.parse(e.content) as { origins?: unknown };
                            const origins = Array.isArray(content.origins)
                                ? content.origins.filter((o): o is string => typeof o === 'string')
                                : [];
                            newest = { created_at: e.created_at, origins };
                        } catch (_) { /* malformed: ignore */ }
                    },
                    onclose: finish,
                },
            );
        } catch (_) {
            finish();
        }
    });
}
