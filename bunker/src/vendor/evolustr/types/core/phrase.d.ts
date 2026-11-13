import type { Bytes } from "./bytes.ts";
import { type EvolustrError, type Result } from "./result.ts";
/** The recovery phrase is R as 12 BIP-39 English words (SPEC §3.1). */
export declare const rootKeyToPhrase: (r: Bytes) => string;
/** Parses a recovery phrase, tolerating extra spaces and capitals. */
export declare const phraseToRootKey: (phrase: string) => Result<Bytes, EvolustrError>;
/**
 * The data secret S as Evolu's own 12-word mnemonic: Evolu opens the same
 * database from it, without Nostr or Evolustr. It is the database key itself.
 */
export declare const dataSecretToEvoluMnemonic: (s: Bytes) => string;
//# sourceMappingURL=phrase.d.ts.map