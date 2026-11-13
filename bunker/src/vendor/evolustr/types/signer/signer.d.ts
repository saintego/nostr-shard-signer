/**
 * `@evolustr/signer` (SPEC §5): the signer side of Evolustr, embedded by a
 * host signer (iframe signer, browser extension, NIP-46 bunker, Android signer).
 *
 * The host supplies what only it knows: who is calling, how to sign, its nsec
 * (if it holds one), and how to ask the user. Everything else lives here.
 */
import { type Bytes, type EvolustrError, type Passkeys, type Relays, type Result, type Sealed, type UnsignedEvent, type NostrEvent } from "../core/index.js";
/** Who is calling, as the host knows it (SPEC §5.2). Never taken from request params. */
export type Caller = {
    readonly identity: "verified";
    readonly origin: string;
} | {
    readonly identity: "verified";
    readonly androidPackage: string;
} | {
    readonly identity: "connection";
    readonly clientPubkey: string;
};
export type SignerWrap = ({
    readonly type: "sk";
} & Sealed) | ({
    readonly type: "passkey";
    readonly rpId: string;
    readonly credId: string;
    /** The passkey was synced (BS flag) when enrolled (#42). */
    readonly synced?: boolean;
} & Sealed);
export interface SignerVault {
    readonly v: 1;
    readonly wraps: ReadonlyArray<SignerWrap>;
}
export type ConfirmRequest = {
    readonly kind: "appKey";
    readonly appId: string;
    readonly identity: Caller["identity"];
} | {
    readonly kind: "enrollPasskey";
};
export interface SignerHost {
    readonly relays: Relays;
    readonly relayUrls: ReadonlyArray<string>;
    /** Stable name of this signer: its origin, extension id, package name or bunker pubkey (SPEC §5.3). */
    readonly signerKey: string;
    /** Signs the signer's own vault event. */
    readonly sign: (event: UnsignedEvent) => Promise<NostrEvent>;
    readonly getPublicKey: () => Promise<string>;
    /** The nsec, for signers that hold it; omit in passthrough mode. */
    readonly getSecretKey?: () => Bytes | null;
    /**
     * False when a third party can recover the nsec (SPEC §5.7). Default true.
     * A function is read on every use, so a host can ask the user and change it
     * at runtime (e.g. OAuth signers, where the user decides).
     */
    readonly allowSkWrap?: boolean | (() => boolean);
    /** Passkeys on the signer's own origin. */
    readonly passkeys?: Passkeys;
    /** Optional device cache for the unlocked M. */
    readonly cache?: {
        readonly get: (pubkey: string) => Promise<Bytes | null>;
        readonly set: (pubkey: string, m: Bytes) => Promise<void>;
        readonly remove: (pubkey: string) => Promise<void>;
        /**
         * The last good signer vault (JSON), kept on the device (#41). Without these,
         * a replaced signer vault on the relays locks out devices that don't have M cached.
         */
        readonly getVault?: (pubkey: string) => Promise<string | null>;
        readonly setVault?: (pubkey: string, json: string) => Promise<void>;
    };
    readonly ui: {
        /** Show a prompt with the verified caller; the host may remember answers. */
        readonly confirm: (request: ConfirmRequest) => Promise<boolean>;
        /** Resolve after the user clicks inside the signer (needed before passkeys and popups). */
        readonly requestGesture: (reason: "unlock" | "enrollPasskey") => Promise<void>;
    };
    readonly knownNsiteGateways?: ReadonlyArray<string>;
    readonly now?: () => number;
    readonly randomBytes?: (length: number) => Bytes;
    readonly timeoutMs?: number;
}
export interface Capabilities {
    readonly identity: Caller["identity"];
    readonly appId: string;
    readonly signerId: string | null;
    readonly ready: boolean;
    readonly signerPasskey: boolean;
    /** M can be recovered on another device: an `sk` wrap, or a synced signer passkey (#42). */
    readonly recoverable: boolean;
    /** M is protected by the nsec (an `sk` wrap): anyone with the nsec can derive app keys (#43). */
    readonly nsecProtected: boolean;
}
export declare const METHODS: readonly ["evolustr_capabilities", "evolustr_get_wrap_key", "evolustr_enroll_passkey"];
export type Method = (typeof METHODS)[number];
export interface EvolustrSigner {
    /** For the host's message handler: `caller` comes from the host, never from params. */
    readonly handle: (method: string, params: ReadonlyArray<unknown>, caller: Caller) => Promise<Result<unknown>>;
    /** No prompt, and never creates or publishes anything (#29). */
    readonly capabilities: (caller: Caller) => Promise<Result<Capabilities>>;
    /** 32-byte key for the caller's app vault (SPEC §5.3). */
    readonly getWrapKey: (caller: Caller) => Promise<Result<Bytes>>;
    readonly enrollPasskey: () => Promise<Result<void>>;
    /** For the host's auto-approve list (SPEC §5.5 rule 2). */
    readonly isProtectedEvent: (event: {
        readonly kind: number;
        readonly tags: ReadonlyArray<ReadonlyArray<string>>;
    }) => boolean;
    readonly appIdFor: (caller: Caller) => Result<string>;
    readonly lock: () => Promise<void>;
}
export declare const parseSignerVault: (json: string) => Result<SignerVault, EvolustrError>;
export declare const MAX_SIGNER_WRAPS = 32;
/** Union of two signer vaults by wrap id; `local` wins on the same id (#41). */
export declare const mergeSignerVaults: (local: SignerVault, fetched: SignerVault) => SignerVault;
/** App identity from the caller only (SPEC §5.2); insecure or malformed callers get none (#30). */
export declare const appIdForCaller: (caller: Caller, knownNsiteGateways?: ReadonlyArray<string>) => Result<string, EvolustrError>;
export declare const isProtectedEvent: EvolustrSigner["isProtectedEvent"];
export declare const createEvolustrSigner: (host: SignerHost) => EvolustrSigner;
//# sourceMappingURL=signer.d.ts.map