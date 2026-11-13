import { type Bytes } from "./bytes.ts";
import { type EvolustrError, type Result } from "./result.ts";
export declare const sha256: (data: Bytes) => Bytes;
export declare const sha256Hex: (data: Bytes | string) => string;
/** HKDF-SHA256 with an empty salt unless one is given. */
export declare const hkdf: (ikm: Bytes, info: string, length?: number, salt?: Bytes) => Bytes;
/** AES-256-GCM ciphertext as stored in vault JSON. */
export interface Sealed {
    readonly iv: string;
    readonly ct: string;
}
/** Encrypts with AES-256-GCM, a random 12-byte IV and the given AAD. */
export declare const seal: (key: Bytes, plaintext: Bytes, aad: string) => Sealed;
/** Decrypts {@link seal} output; fails on a wrong key, wrong AAD or tampering. */
export declare const open: (key: Bytes, sealed: Sealed, aad: string) => Result<Bytes, EvolustrError>;
//# sourceMappingURL=crypto.d.ts.map