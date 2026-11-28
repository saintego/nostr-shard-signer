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
    readonly tag?: string;
} & Sealed) | ({
    readonly type: "passkey";
    readonly rpId: string;
    readonly credId: string;
    /** The passkey was synced (BS flag) when enrolled (#42). */
    readonly synced?: boolean;
    /**
     * HMAC under a key derived from M over the wrap's fields (#54). Wraps from
     * older versions have none.
     */
    readonly tag?: string;
} & Sealed);
export interface SignerVault {
    readonly v: 1;
    readonly wraps: ReadonlyArray<SignerWrap>;
    /**
     * Unix seconds when an `sk` wrap was removed for this M (#52). M didn't
     * change, so anyone who can recover the nsec may still open an older copy.
     */
    readonly skDroppedAt?: number;
    /** Public id of the M this vault holds (#52 phase B); missing in older vaults. */
    readonly mId?: string;
    /** Set after {@link EvolustrSigner.rotateMaster}: the previous M authorises this one. */
    readonly rotatedFrom?: {
        readonly mId: string;
        readonly proof: string;
    };
    /** The previous M, sealed with a key from this M, so apps can still open their old wrap. */
    readonly previous?: PreviousMaster;
    /**
     * The Ms before `previous`, newest first (#58): each sealed with a key from
     * the one before it in this chain (`older[0]` with `previous`'s M). Carried
     * over unchanged at each rotation, at most {@link MAX_PREVIOUS_MASTERS} in all.
     */
    readonly older?: ReadonlyArray<PreviousMaster>;
}
/** An earlier M, sealed with `HKDF(M_next, "evolustr/v1/signer-previous")` (#52 phase B, #58). */
export type PreviousMaster = {
    readonly mId: string;
} & Sealed;
/** How many earlier Ms a signer vault keeps (`previous` plus `older`, #58). */
export declare const MAX_PREVIOUS_MASTERS = 16;
export type ConfirmRequest = {
    readonly kind: "appKey";
    readonly appId: string;
    readonly identity: Caller["identity"];
} | {
    readonly kind: "enrollPasskey";
} | {
    readonly kind: "rotateMaster";
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
        readonly requestGesture: (reason: "unlock" | "enrollPasskey" | "rotateMaster") => Promise<void>;
    };
    readonly knownNsiteGateways?: ReadonlyArray<string>;
    readonly now?: () => number;
    readonly randomBytes?: (length: number) => Bytes;
    readonly timeoutMs?: number;
    /**
     * Enough relays to trust a vault an unlock found (#60): such reads stop
     * waiting once this many answered, so one slow relay doesn't hold them up.
     * "No vault" and reads before a write still wait for every relay (#62).
     * Default: every relay.
     */
    readonly relayQuorum?: number;
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
    /**
     * The nsec could open M now or did before (an `sk` wrap, or one removed for
     * this M): anyone who can recover the nsec may have M and every app key (#52).
     */
    readonly nsecExposed: boolean;
    /**
     * After a key rotation (#52 phase B): this app's signer id under the previous
     * M, so the client can open its old wrap and then replace its root key.
     */
    readonly previousSignerId: string | null;
    /**
     * Every earlier M's signer id for this app, newest first (#58): an app that
     * skipped rotations finds the one its wrap used and asks for that key.
     * `previousSignerIds[0]` is `previousSignerId`.
     */
    readonly previousSignerIds: ReadonlyArray<string>;
}
export declare const METHODS: readonly ["evolustr_capabilities", "evolustr_get_wrap_key", "evolustr_get_previous_wrap_key", "evolustr_enroll_passkey"];
export type Method = (typeof METHODS)[number];
export interface EvolustrSigner {
    /** For the host's message handler: `caller` comes from the host, never from params. */
    readonly handle: (method: string, params: ReadonlyArray<unknown>, caller: Caller) => Promise<Result<unknown>>;
    /** No prompt, and never creates or publishes anything (#29). */
    readonly capabilities: (caller: Caller) => Promise<Result<Capabilities>>;
    /** 32-byte key for the caller's app vault (SPEC §5.3). */
    readonly getWrapKey: (caller: Caller) => Promise<Result<Bytes>>;
    readonly enrollPasskey: () => Promise<Result<void>>;
    /**
     * The caller's key under an earlier M, after {@link rotateMaster} (#52 phase
     * B): the one whose signer id for this app is `signerId` (#58), else the
     * previous one.
     */
    readonly getPreviousWrapKey: (caller: Caller, signerId?: string) => Promise<Result<Bytes>>;
    /**
     * Replaces M with a new one, from a click in the signer's own UI (#52 phase
     * B). Needs a signer passkey and `allowSkWrap` false. Only the passkey used
     * here wraps the new M: other signer passkeys must be enrolled again.
     */
    readonly rotateMaster: () => Promise<Result<{
        readonly droppedWraps: number;
    }>>;
    /**
     * 32-byte secret from M for the host's own use (§5.6), e.g. its synced
     * settings. Host-only: no `handle()` method reaches it, so apps can't ask for
     * it. Unlocks M like `getWrapKey` (passkey if needed), without the app prompt.
     */
    readonly getHostSecret: (label: string) => Promise<Result<Bytes>>;
    /**
     * The same host secret under the previous M, after {@link rotateMaster}, so
     * the host can move its own data across, like apps with getPreviousWrapKey.
     */
    readonly getPreviousHostSecret: (label: string) => Promise<Result<Bytes>>;
    /** The host secret under every earlier M, newest first (#58); empty before any rotation. */
    readonly getPreviousHostSecrets: (label: string) => Promise<Result<ReadonlyArray<Bytes>>>;
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
/** Above this many wraps, untagged ones are dropped once M is unlocked (#54). */
export declare const UNTAGGED_SIGNER_WRAP_LIMIT = 16;
/**
 * Union of two signer vaults by wrap id; `local` wins on the same id (#41).
 * With `dropSk`, `sk` wraps are left out (#52): a relay vault without one is
 * never "healed" back to one by a device that may not use it.
 */
export declare const mergeSignerVaults: (local: SignerVault, fetched: SignerVault, opts?: {
    readonly dropSk?: boolean;
}) => SignerVault;
/** Two versions of the signer vault hold different master secrets: never merge them (#52 phase B). */
export declare const differentMaster: (a: SignerVault, b: SignerVault) => boolean;
/** Proof that the M behind `oldMId` authorised `newMId` (#52 phase B). */
export declare const masterRotationProof: (oldM: Bytes, newMId: string) => string;
type UntaggedSignerWrap = {
    readonly type: "sk";
    readonly iv: string;
    readonly ct: string;
} | {
    readonly type: "passkey";
    readonly rpId: string;
    readonly credId: string;
    readonly synced?: boolean;
    readonly iv: string;
    readonly ct: string;
};
/** HMAC tag of a signer-vault wrap under a key derived from M (#54). Covers `synced` too. */
export declare const signerWrapTag: (pubkey: string, signerKey: string, m: Bytes, w: UntaggedSignerWrap) => string;
/**
 * Once M is known (#54): drops wraps whose tag is wrong. Untagged wraps from
 * older versions are kept, unless the vault has more than
 * {@link UNTAGGED_SIGNER_WRAP_LIMIT} wraps: then only the one just opened stays.
 */
export declare const pruneSignerVault: (vault: SignerVault, pubkey: string, signerKey: string, m: Bytes, openedId?: string) => SignerVault;
/** App identity from the caller only (SPEC §5.2); insecure or malformed callers get none (#30). */
export declare const appIdForCaller: (caller: Caller, knownNsiteGateways?: ReadonlyArray<string>) => Result<string, EvolustrError>;
export declare const isProtectedEvent: EvolustrSigner["isProtectedEvent"];
export declare const createEvolustrSigner: (host: SignerHost) => EvolustrSigner;
export {};
//# sourceMappingURL=signer.d.ts.map