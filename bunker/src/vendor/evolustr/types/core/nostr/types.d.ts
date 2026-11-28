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
    /** Relays that failed or timed out, or weren't waited for. */
    readonly failed: ReadonlyArray<string>;
    /**
     * The relays in `failed` that may still hold an answer: they timed out, or a
     * quorum read stopped waiting for them (#62). The others failed hard
     * (refused the connection, closed the subscription). Without it, every
     * failed relay counts as pending.
     */
    readonly pending?: ReadonlyArray<string>;
    /** Event ids each answering relay returned, to find relays that lack the newest version. */
    readonly idsByRelay?: ReadonlyMap<string, ReadonlySet<string>>;
    /** A quorum read that stopped early: the result once every relay answered or the timeout passed. */
    readonly rest?: Promise<QueryResult>;
}
export interface PublishResult {
    readonly accepted: ReadonlyArray<string>;
    readonly failed: ReadonlyArray<string>;
    /** Failed relays that didn't answer in time; retrying them right away only adds waiting. */
    readonly timedOut?: ReadonlyArray<string>;
}
/** Relay access behind an interface, so tests can use an in-memory fake. */
export interface QueryOptions {
    /**
     * Stop waiting once this many relays have answered (#60): one slow relay
     * mustn't hold up the read. Relays still waiting then count as failed and
     * pending, and `rest` gives the full result. Default: every relay.
     */
    readonly quorum?: number;
}
export interface Relays {
    readonly query: (urls: ReadonlyArray<string>, filter: Filter, timeoutMs: number, opts?: QueryOptions) => Promise<QueryResult>;
    readonly publish: (urls: ReadonlyArray<string>, event: NostrEvent, timeoutMs: number) => Promise<PublishResult>;
}
//# sourceMappingURL=types.d.ts.map