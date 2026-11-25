import type { NostrEvent, Relays, Signer, UnsignedEvent } from "./types.ts";
export type FetchedEvent = {
    readonly kind: "found";
    readonly event: NostrEvent;
    readonly complete: boolean;
    /** Relays that answered without this newest version; send it to them (#32). */
    readonly missingOn: ReadonlyArray<string>;
}
/**
 * No relay has the event, and every relay answered or failed hard (refused
 * the connection): none may still hold it (#62). A quorum never decides this.
 */
 | {
    readonly kind: "none";
}
/** No event found, but not enough relays answered: don't treat it as missing. */
 | {
    readonly kind: "incomplete";
};
export interface Address {
    readonly author: string;
    readonly kind: number;
    readonly d: string;
}
/** Newest wins; on equal `created_at`, the lowest id (NIP-01). */
export declare const newest: (events: ReadonlyArray<NostrEvent>) => NostrEvent | undefined;
/**
 * Fetches the newest replaceable event at an address. Waits for every relay,
 * or with `quorum` until that many answered (#60), which is for reads that
 * only unlock: "found" may come from the quorum, "none" never does (#62). With
 * nothing found at the quorum, it waits for the other relays.
 *
 * Before publishing a new version, read without `quorum`: a version found at
 * the quorum may be stale, and a write based on it would replace a newer one.
 */
export declare const fetchReplaceable: (relays: Relays, urls: ReadonlyArray<string>, address: Address, timeoutMs?: number, quorum?: number) => Promise<FetchedEvent>;
/**
 * Signs and publishes a replaceable event; succeeds if at least one relay
 * accepts it. Relays that refused get one more try with the same signed event;
 * `failed` lists those that still refused.
 */
export declare const publishReplaceable: (relays: Relays, urls: ReadonlyArray<string>, signer: Signer, event: UnsignedEvent, timeoutMs?: number) => Promise<{
    readonly event: NostrEvent;
    readonly accepted: ReadonlyArray<string>;
    readonly failed: ReadonlyArray<string>;
}>;
//# sourceMappingURL=replaceable.d.ts.map