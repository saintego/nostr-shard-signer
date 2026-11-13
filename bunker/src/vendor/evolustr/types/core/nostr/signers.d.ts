import type { NostrEvent, Signer, UnsignedEvent } from "./types.ts";
/** The NIP-07 `window.nostr` shape (with NIP-44). */
export interface Nip07 {
    readonly getPublicKey: () => Promise<string>;
    readonly signEvent: (event: UnsignedEvent) => Promise<NostrEvent>;
    readonly nip44?: {
        readonly encrypt: (pubkey: string, plaintext: string) => Promise<string>;
        readonly decrypt: (pubkey: string, ciphertext: string) => Promise<string>;
    };
}
/** Wraps a NIP-07 provider; fails clearly when it has no NIP-44. */
export declare const nip07Signer: (nostr: Nip07) => Signer;
/** A signer holding the secret key in memory (tests, and signers that hold the nsec). */
export declare const secretKeySigner: (secretKey: Uint8Array) => Signer;
/** The parts of a NIP-46 client (e.g. nostr-tools `BunkerSigner`) that Evolustr uses. */
export interface Nip46Client {
    readonly getPublicKey: () => Promise<string>;
    readonly signEvent: (event: {
        kind: number;
        created_at: number;
        tags: string[][];
        content: string;
    }) => Promise<NostrEvent>;
    readonly nip44Encrypt: (pubkey: string, plaintext: string) => Promise<string>;
    readonly nip44Decrypt: (pubkey: string, ciphertext: string) => Promise<string>;
}
/** A remote bunker (NIP-46) as a {@link Signer}; works on web and in React Native. */
export declare const nip46Signer: (bunker: Nip46Client) => Signer;
//# sourceMappingURL=signers.d.ts.map