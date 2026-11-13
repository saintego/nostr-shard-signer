export type Bytes = Uint8Array;
export declare const utf8: (text: string) => Bytes;
export declare const fromUtf8: (bytes: Bytes) => string;
export declare const randomBytes: (length: number) => Bytes;
export declare const toHex: (bytes: Bytes) => string;
export declare const fromHex: (hex: string) => Bytes | null;
export declare const toBase64Url: (bytes: Bytes) => string;
export declare const fromBase64Url: (text: string) => Bytes | null;
export declare const concat: (...parts: ReadonlyArray<Bytes>) => Bytes;
/** Constant-time comparison for equal-length secrets. */
export declare const bytesEqual: (a: Bytes, b: Bytes) => boolean;
//# sourceMappingURL=bytes.d.ts.map