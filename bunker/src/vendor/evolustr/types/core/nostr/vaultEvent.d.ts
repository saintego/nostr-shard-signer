import { type EvolustrError, type Result } from "../result.ts";
import { type Vault, type VaultContext } from "../vault.ts";
import type { NostrEvent, Signer, UnsignedEvent } from "./types.ts";
import type { Bytes } from "../bytes.ts";
/** The unsigned kind-30078 event for an app vault (SPEC §6.1). */
export declare const vaultEvent: (ctx: VaultContext, vault: Vault, now: number) => UnsignedEvent;
/** Parses a fetched vault event, checking author and `d`-tag. */
export declare const readVaultEvent: (ctx: VaultContext, event: NostrEvent) => Result<Vault, EvolustrError>;
/** NIP-44 self-encryption of S (the `nip44` data wrap). */
export declare const nip44SealSecret: (signer: Signer, pubkey: string, s: Bytes) => Promise<string>;
/** Opens the `nip44` data wrap through the signer and checks it against `sHash`. */
export declare const nip44OpenSecret: (signer: Signer, pubkey: string, vault: Vault) => Promise<Result<Bytes, EvolustrError>>;
//# sourceMappingURL=vaultEvent.d.ts.map