import { type Bytes } from "./bytes.ts";
import { type Sealed } from "./crypto.ts";
import { type EvolustrError, type Result } from "./result.ts";
export type Mode = "compatible" | "strict";
/**
 * A wrap of R. `tag` is an HMAC under a key derived from R over the wrap's
 * fields (#37): only someone holding R can add or change a root wrap.
 */
export type RootWrap = ({
    readonly type: "signer";
    readonly signerId: string;
    readonly tag: string;
} & Sealed) | ({
    readonly type: "passkey";
    readonly rpId: string;
    readonly credId: string;
    readonly tag: string;
} & Sealed);
/** A root wrap before its tag is computed. */
export type UntaggedRootWrap = ({
    readonly type: "signer";
    readonly signerId: string;
} & Sealed) | ({
    readonly type: "passkey";
    readonly rpId: string;
    readonly credId: string;
} & Sealed);
export type DataWrap = ({
    readonly type: "root";
} & Sealed) | {
    readonly type: "nip44";
    readonly ct: string;
};
export interface HistoryEntry {
    readonly sHash: string;
    readonly created: number;
}
export interface Vault {
    readonly v: 1;
    readonly mode: Mode;
    /** Unix seconds when the current S was created. */
    readonly created: number;
    readonly sHash: string;
    /** Earlier data secrets, oldest first, at most {@link HISTORY_LIMIT}. */
    readonly history: ReadonlyArray<HistoryEntry>;
    readonly rootWraps: ReadonlyArray<RootWrap>;
    readonly dataWraps: ReadonlyArray<DataWrap>;
}
/** Who and which app a vault belongs to; part of every AAD. */
export interface VaultContext {
    readonly pubkey: string;
    readonly appId: string;
}
export declare const HISTORY_LIMIT = 10;
export declare const MAX_ROOT_WRAPS = 32;
export declare const level: (vault: Vault) => "strong" | "weak";
export declare const nip44Wrap: (vault: Vault) => Extract<DataWrap, {
    type: "nip44";
}> | undefined;
export declare const rootDataWrap: (vault: Vault) => Extract<DataWrap, {
    type: "root";
}> | undefined;
/** True when the vault has a root key R (a `root` data wrap exists). */
export declare const hasRootKey: (vault: Vault) => boolean;
export declare const rootWrapKeyId: (wrap: RootWrap) => string;
export declare const signerWrapFor: (vault: Vault, signerId: string) => RootWrap | undefined;
export declare const passkeyWrapsFor: (vault: Vault, rpId: string) => ReadonlyArray<Extract<RootWrap, {
    type: "passkey";
}>>;
/** Checks the rules a stored vault must satisfy (SPEC §3.2, §6.1). */
export declare const validateVault: (vault: Vault) => Result<Vault, EvolustrError>;
/** Parses vault JSON (event content) and checks its rules. */
export declare const parseVault: (json: string) => Result<Vault, EvolustrError>;
export declare const serializeVault: (vault: Vault) => string;
/** The vault fields the `root` data wrap authenticates (SPEC §3.1, §6.3). */
export interface VaultHeader {
    readonly mode: Mode;
    readonly created: number;
    readonly sHash: string;
    readonly history: ReadonlyArray<HistoryEntry>;
}
/**
 * Binds the header into the root data wrap's AAD: a header that was edited, or
 * replayed from an older vault with a newer history, no longer opens with R.
 */
export declare const headerBinding: (h: VaultHeader) => string;
/** Wraps R for a capable signer, keyed by the signer's app key (SPEC §3.1). */
export declare const signerRootWrap: (ctx: VaultContext, signerAppKey: Bytes, signerId: string, r: Bytes) => RootWrap;
/** Wraps R for a client passkey, keyed by its PRF-derived wrap key (SPEC §4.2). */
export declare const passkeyRootWrap: (ctx: VaultContext, wrapKey: Bytes, rpId: string, credId: string, r: Bytes) => RootWrap;
/** HMAC tag of a root wrap under {@link wrapAuthKey} (SPEC §3.1, #37). */
export declare const rootWrapTag: (ctx: VaultContext, r: Bytes, wrap: UntaggedRootWrap) => string;
/** True when the wrap's tag was made with this R. */
export declare const verifyRootWrap: (ctx: VaultContext, r: Bytes, wrap: RootWrap) => boolean;
/** Opens one root wrap with its key, giving R. */
export declare const openRootWrap: (ctx: VaultContext, wrap: RootWrap, key: Bytes) => Result<Bytes, EvolustrError>;
/** Opens the `root` data wrap with R and checks the result against `sHash`. */
export declare const openRootData: (ctx: VaultContext, vault: Vault, r: Bytes) => Result<Bytes, EvolustrError>;
/** Same header and same data wraps (root: iv+ct, nip44: ct). Root wraps are not compared (#38). */
export declare const sameVaultCore: (a: Vault, b: Vault) => boolean;
/** Checks a decrypted nip44 payload against the vault's `sHash`. */
export declare const checkDataSecret: (vault: Vault, s: Bytes) => Result<Bytes, EvolustrError>;
export interface CreateCompatibleInput {
    readonly s: Bytes;
    /** NIP-44 self-encryption of S (base64url of S as plaintext), made by the signer. */
    readonly nip44Ct: string;
    readonly now: number;
    /** Set when a strong method or the phrase already exists at creation. */
    readonly r?: Bytes;
    readonly rootWraps?: ReadonlyArray<RootWrap>;
}
/** A new `compatible` vault (SPEC §3.2 rule 1). */
export declare const createCompatibleVault: (ctx: VaultContext, input: CreateCompatibleInput) => Result<Vault, EvolustrError>;
export interface CreateStrictInput {
    readonly s: Bytes;
    readonly r: Bytes;
    readonly now: number;
    readonly rootWraps: ReadonlyArray<RootWrap>;
}
/** A new vault created `strict` directly, for `requireStrong` (SPEC §3.2 rule 1). */
export declare const createStrictVault: (ctx: VaultContext, input: CreateStrictInput) => Result<Vault, EvolustrError>;
/** Adds R to a vault that has none yet (first strong method or confirmed phrase). */
export declare const addRootKey: (ctx: VaultContext, vault: Vault, r: Bytes, s: Bytes) => Result<Vault, EvolustrError>;
/** Adds or replaces a root wrap, keyed by `signerId` / `credId` (SPEC §6.2 rule 3). */
export declare const addRootWrap: (vault: Vault, wrap: RootWrap) => Result<Vault, EvolustrError>;
/**
 * Removes one root wrap; only on an explicit user action (SPEC §6.2 rule 3).
 * TODO(#37): the client never calls this. With "never drop a wrap", a removal
 * would need a tombstone authenticated with R.
 */
export declare const removeRootWrap: (vault: Vault, type: RootWrap["type"], keyId: string) => Vault;
export interface MakeStrictInput {
    readonly r: Bytes;
    readonly newS: Bytes;
    readonly now: number;
}
/**
 * Makes a vault strict with a new data secret S' (SPEC §3.2 rule 4, §3.4).
 * Root wraps and R stay; the nip44 wrap is dropped; the old S goes into history.
 */
export declare const makeStrict: (ctx: VaultContext, vault: Vault, input: MakeStrictInput) => Result<Vault, EvolustrError>;
export interface DowngradeInput {
    readonly r: Bytes;
    readonly s: Bytes;
    /** NIP-44 self-encryption of the current S. */
    readonly nip44Ct: string;
}
/**
 * Turns strict off by adding a nip44 wrap of the current S (SPEC §3.2 rule 7).
 * The root data wrap is sealed again, because the mode is part of its AAD.
 */
export declare const downgrade: (ctx: VaultContext, vault: Vault, input: DowngradeInput) => Result<Vault, EvolustrError>;
/**
 * Merges two versions of the same vault (same S) after concurrent updates:
 * the union of root wraps, keyed by `signerId` / `credId` (SPEC §6.2 rule 3).
 * Never adds a nip44 wrap to a strict result (SPEC §3.2 rule 5).
 */
export declare const mergeVaults: (a: Vault, b: Vault, opts?: {
    readonly ctx: VaultContext;
    readonly r?: Bytes | undefined;
}) => Result<Vault, EvolustrError>;
/**
 * Cut-off for copying local rows after a rotation (SPEC §3.4 step 2): the
 * `created` time of the secret that replaced the local one. `null` when the
 * local secret isn't in the history (ask the user before copying).
 */
export declare const migrationCutoff: (vault: Vault, localSHash: string) => number | null;
export type StrongMethod = {
    readonly kind: "passkey";
    readonly synced: boolean;
} | {
    readonly kind: "signer";
    readonly recoverable: boolean;
};
export type BackupRequirement = "none" | "reminder" | "required";
/**
 * Backup check before `strict` (SPEC §3.2 rule 3a): nothing when a backup
 * already exists, a skippable reminder when the only method recovers on its
 * own, otherwise a backup (or explicit acceptance) is required.
 */
export declare const backupRequirement: (methods: ReadonlyArray<StrongMethod>, phraseConfirmed: boolean) => BackupRequirement;
//# sourceMappingURL=vault.d.ts.map