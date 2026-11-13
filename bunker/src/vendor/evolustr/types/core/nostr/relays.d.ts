import { SimplePool } from "nostr-tools/pool";
import type { NostrEvent, Relays } from "./types.ts";
/** Relays over nostr-tools, tracking EOSE per relay (SPEC §6.2 rule 1). */
export declare const poolRelays: (pool?: SimplePool) => Relays;
/**
 * In-memory relays for tests. Each URL is a separate store; URLs in `down`
 * fail every request. Replaceable events (kind 30000–39999) keep only the newest.
 */
export declare const memoryRelays: (opts?: {
    readonly down?: Set<string>;
}) => {
    relays: Relays;
    down: Set<string>;
    put: (url: string, event: NostrEvent) => void;
    store: (url: string) => NostrEvent[];
};
//# sourceMappingURL=relays.d.ts.map