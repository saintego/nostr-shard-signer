/**
 * Transport adapters for {@link EvolustrSigner} (SPEC §5.1). Each one turns a
 * transport's request into `handle(method, params, caller)`, taking the caller
 * from the transport itself.
 */
import type { Result } from "../core/index.js";
import type { EvolustrSigner } from "./signer.ts";
/** postMessage envelope used between the app page and an iframe signer. */
export interface IframeRequest {
    readonly type: "evolustr";
    readonly id: string;
    readonly method: string;
    readonly params?: ReadonlyArray<unknown>;
}
export interface IframeResponse {
    readonly type: "evolustr";
    readonly id: string;
    readonly result?: unknown;
    readonly error?: {
        readonly type: string;
        readonly message: string;
    };
}
export declare const isIframeRequest: (data: unknown) => data is IframeRequest;
/**
 * Which app pages may call the signer. Required (#30): without it any site
 * could embed the signer, and the only gate would be a prompt drawn inside an
 * embeddable frame, which is open to clickjacking. Pass the embedding page's
 * origin (e.g. from `location.ancestorOrigins`), a list, or a predicate.
 */
export type AllowedOrigins = string | ReadonlyArray<string> | ((origin: string) => boolean);
/**
 * Handles one message inside an iframe signer. The caller is `event.origin`,
 * which the browser sets, and only allowed origins are served. Reply with
 * `postMessage(response, event.origin)`, never with "*".
 */
export declare const handleIframeMessage: (signer: EvolustrSigner, event: {
    readonly origin: string;
    readonly data: unknown;
}, allowedOrigins: AllowedOrigins) => Promise<IframeResponse | null>;
/** Wires {@link handleIframeMessage} to a window; returns a function that stops listening. */
export declare const listenForIframeRequests: (signer: EvolustrSigner, self: Pick<Window, "addEventListener" | "removeEventListener">, reply: (response: IframeResponse, origin: string) => void, allowedOrigins: AllowedOrigins) => (() => void);
/** NIP-46: `evolustr_*` request from a connected client; results are strings. */
export declare const handleNip46Request: (signer: EvolustrSigner, clientPubkey: string, request: {
    readonly id: string;
    readonly method: string;
    readonly params: ReadonlyArray<string>;
}) => Promise<{
    readonly id: string;
    readonly result?: string;
    readonly error?: string;
}>;
/** Browser extension: the sender's origin comes from the extension runtime. */
export declare const handleExtensionRequest: (signer: EvolustrSigner, senderOrigin: string, method: string, params?: ReadonlyArray<unknown>) => Promise<Result<unknown>>;
//# sourceMappingURL=adapters.d.ts.map