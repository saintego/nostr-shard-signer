import { type Bytes } from "./bytes.ts";
/** Root key R and data secret S are 16 bytes (12 BIP-39 words). Signer master M is 32 bytes. */
export declare const ROOT_KEY_LENGTH = 16;
export declare const DATA_SECRET_LENGTH = 16;
export declare const MASTER_SECRET_LENGTH = 32;
/** First 8 bytes of SHA-256(S), hex (SPEC §6.1). */
export declare const sHash: (s: Bytes) => string;
/** Key for the `root` data wrap: HKDF(R, "evolustr/v1/data|" + appId) (SPEC §3.1). */
export declare const rootDataKey: (r: Bytes, appId: string) => Bytes;
/** Key for root-wrap tags (SPEC §3.1, #37): only holders of R can make a valid tag. */
export declare const wrapAuthKey: (r: Bytes, appId: string) => Bytes;
/** HMAC key the old R uses to authorise a root rotation (#52 phase C). */
export declare const rootRotateKey: (r: Bytes, appId: string) => Bytes;
/** PRF input shared by all client passkeys of one vault (SPEC §4.1). */
export declare const clientPrfInput: (pubkey: string, appId: string) => Bytes;
/** Wrap key from a client passkey's PRF output (SPEC §4.1). */
export declare const passkeyWrapKey: (prfOutput: Bytes, appId: string) => Bytes;
/** PRF input for a signer passkey (SPEC §5.3). */
export declare const signerPrfInput: (pubkey: string) => Bytes;
/** Wrap key for M from a signer passkey's PRF output. */
export declare const signerPasskeyWrapKey: (prfOutput: Bytes) => Bytes;
/** Wrap key for M from the nsec (`sk` wrap, SPEC §5.3). */
export declare const signerSkWrapKey: (secretKey: Bytes) => Bytes;
/** HMAC key for signer-vault wrap tags (#54): only a holder of M can tag a wrap. */
export declare const signerWrapAuthKey: (m: Bytes) => Bytes;
/** Public id of a signer master secret, kept in the signer vault (#52 phase B). */
export declare const signerMId: (m: Bytes) => string;
/** HMAC key the old M uses to authorise its successor (#52 phase B). */
export declare const signerRotateKey: (m: Bytes) => Bytes;
/** Key the new M seals the previous M with, so old app keys stay available (#52 phase B). */
export declare const signerPreviousKey: (m: Bytes) => Bytes;
/** Per-app key a capable signer gives the caller (SPEC §5.3). */
export declare const signerAppKey: (m: Bytes, appId: string) => Bytes;
/**
 * A secret the host signer derives from M for its own use (§5.6), e.g. the key
 * of its synced settings. Namespaced apart from app keys (`evolustr/v1|app|…`),
 * so a label can never yield an app's key. Labels are non-empty and contain no
 * `|`; the host checks that with `isHostSecretLabel`.
 */
export declare const hostSecret: (m: Bytes, label: string) => Bytes;
/** A valid label for `hostSecret`: 1–200 characters, no `|`. */
export declare const isHostSecretLabel: (label: string) => boolean;
/**
 * Label of a signer's wrap inside one app's vault (SPEC §5.3). Derived per app,
 * so apps can't use it to link the same user across apps (#29).
 */
export declare const signerId: (m: Bytes, appId: string) => string;
//# sourceMappingURL=keys.d.ts.map