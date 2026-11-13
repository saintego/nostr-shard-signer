/** Kind for all Evolustr events (NIP-78 application data). */
export declare const VAULT_KIND = 30078;
/** Prefix that lets signers recognise Evolustr events (SPEC §5.5 rule 2). */
export declare const PROTECTED_DTAG_PREFIX = "evolustr:";
/** `d`-tag of an app vault; includes the pubkey so tags differ per user (SPEC §6.1). */
export declare const appVaultDTag: (pubkey: string, appId: string) => string;
/** `d`-tag of a signer's own vault, found before M is known (SPEC §5.3). */
export declare const signerVaultDTag: (pubkey: string, signerKey: string) => string;
/** `d`-tag of the shared settings event (SPEC §9.1). */
export declare const SETTINGS_DTAG = "evolustr:settings:v1";
export declare const isProtectedDTag: (d: string) => boolean;
//# sourceMappingURL=tags.d.ts.map