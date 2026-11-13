/** Minimal Nostr shapes Evolustr needs (NIP-01). */
export interface NostrEvent {
    readonly id: string;
    readonly pubkey: string;
    readonly created_at: number;
    readonly kind: number;
    readonly tags: ReadonlyArray<ReadonlyArray<string>>;
    readonly content: string;
    readonly sig: string;
}
export interface UnsignedEvent {
    readonly kind: number;
    readonly created_at: number;
    readonly tags: ReadonlyArray<ReadonlyArray<string>>;
    readonly content: string;
}
export interface Filter {
    readonly kinds?: ReadonlyArray<number>;
    readonly authors?: ReadonlyArray<string>;
    readonly "#d"?: ReadonlyArray<string>;
    readonly limit?: number;
}
/** What Evolustr needs from a signer: NIP-07 shape, NIP-44 only. */
export interface Signer {
    readonly getPublicKey: () => Promise<string>;
    readonly signEvent: (event: UnsignedEvent) => Promise<NostrEvent>;
    readonly nip44Encrypt: (peerPubkey: string, plaintext: string) => Promise<string>;
    readonly nip44Decrypt: (peerPubkey: string, ciphertext: string) => Promise<string>;
}
export interface QueryResult {
    readonly events: ReadonlyArray<NostrEvent>;
    /** Relays that sent EOSE before the timeout. */
    readonly answered: ReadonlyArray<string>;
    /** Relays that failed or timed out. */
    readonly failed: ReadonlyArray<string>;
    /** Event ids each answering relay returned, to find relays that lack the newest version. */
    readonly idsByRelay?: ReadonlyMap<string, ReadonlySet<string>>;
}
export interface PublishResult {
    readonly accepted: ReadonlyArray<string>;
    readonly failed: ReadonlyArray<string>;
    /** Failed relays that didn't answer in time; retrying them right away only adds waiting. */
    readonly timedOut?: ReadonlyArray<string>;
}
/** Relay access behind an interface, so tests can use an in-memory fake. */
export interface Relays {
    readonly query: (urls: ReadonlyArray<string>, filter: Filter, timeoutMs: number) => Promise<QueryResult>;
    readonly publish: (urls: ReadonlyArray<string>, event: NostrEvent, timeoutMs: number) => Promise<PublishResult>;
}
//# sourceMappingURL=types.d.ts.map