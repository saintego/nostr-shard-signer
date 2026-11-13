import { type Bytes } from "./bytes.ts";
export interface PasskeyResult {
    readonly credId: string;
    /** PRF output, or null when the authenticator didn't return one. */
    readonly prfOutput: Bytes | null;
    /** WebAuthn backup-state flag (BS): the passkey is synced (SPEC §3.2 rule 3a). */
    readonly synced: boolean;
}
export interface CreatedPasskey extends PasskeyResult {
    /** PRF is supported, even if no output came with `create()` (SPEC §4.2 step 4). */
    readonly prfEnabled: boolean;
}
export interface Passkeys {
    readonly rpId: string;
    readonly supported: () => Promise<boolean>;
    readonly create: (args: {
        readonly userId: Bytes;
        readonly userName: string;
        readonly excludeCredIds: ReadonlyArray<string>;
        readonly prfInput: Bytes;
    }) => Promise<CreatedPasskey>;
    readonly get: (args: {
        readonly allowCredIds: ReadonlyArray<string>;
        readonly prfInput: Bytes;
    }) => Promise<PasskeyResult>;
}
/** WebAuthn in the browser. Call `create` and `get` only from a user gesture. */
export declare const webauthnPasskeys: (opts: {
    readonly rpId?: string;
    readonly rpName: string;
}) => Passkeys;
/**
 * A simulated authenticator for tests. Credentials live in `store`; pass the
 * same store to two devices to simulate a synced passkey provider.
 */
export declare const memoryPasskeys: (opts: {
    readonly rpId: string;
    readonly store?: Map<string, Bytes>;
    readonly synced?: boolean;
    readonly prfAtCreate?: boolean;
    readonly prf?: boolean;
    /** The credential the "user" picks in `get`; defaults to the first allowed one present. */
    readonly pick?: (allowed: ReadonlyArray<string>) => string | undefined;
}) => Passkeys & {
    readonly store: Map<string, Bytes>;
};
//# sourceMappingURL=passkeys.d.ts.map