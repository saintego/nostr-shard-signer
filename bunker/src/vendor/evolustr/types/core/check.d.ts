/**
 * Decides what a device does with the vault it fetched (SPEC §6.3).
 * Pure: the caller supplies what it fetched and what it already knows.
 */
import type { Bytes } from "./bytes.ts";
import { type Vault, type VaultContext } from "./vault.ts";
export type Fetched = {
    readonly kind: "found";
    readonly vault: Vault;
}
/** Every relay answered and none has a vault. */
 | {
    readonly kind: "none";
}
/** A vault event exists but can't be parsed, or relays didn't all answer. */
 | {
    readonly kind: "unreadable";
};
export interface LocalState {
    /** `sHash` of the local database for this (pubkey, appId). */
    readonly sHash: string;
    /** R, if this device knows it (cached or just unlocked). */
    readonly r?: Bytes;
    /** The last good vault, as kept in the app database (SPEC §6.2 rule 5). */
    readonly copy?: Vault;
    /** Data secrets this device has moved past, kept locally beyond the vault's history limit (#44). */
    readonly seen?: ReadonlyArray<string>;
}
export type VaultChoice = "republishCopy" | "followRelay" | "restorePhrase" | "startNew";
export type VaultDecision = 
/** No local database: unlock normally; warn about the weak level before first use. */
{
    readonly type: "firstUse";
    readonly vault: Vault;
    readonly warnWeak: boolean;
}
/** No vault anywhere and no local database: create one. */
 | {
    readonly type: "create";
} | {
    readonly type: "same";
}
/** A rotation this device can verify (its secret is in the vault's history): follow and migrate. */
 | {
    readonly type: "follow";
    readonly vault: Vault;
    readonly s: Bytes;
    readonly cutoff: number | null;
}
/** The device can't verify a strict vault: needs a strong method or the phrase. */
 | {
    readonly type: "needsStrongUnlock";
    readonly vault: Vault;
}
/** The user must choose; `options` lists what is safe to offer. */
 | {
    readonly type: "choose";
    readonly reason: "replaced" | "ambiguous" | "missing";
    readonly vault?: Vault;
    readonly options: ReadonlyArray<VaultChoice>;
};
export declare const decideVault: (ctx: VaultContext, fetched: Fetched, local: LocalState | null) => VaultDecision;
//# sourceMappingURL=check.d.ts.map