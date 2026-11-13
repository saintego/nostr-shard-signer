import type { NostrEvent } from "./types.ts";
/**
 * Checks id and signature on a clean copy. nostr-tools caches a successful
 * check on the event object itself, and a copied object would keep that flag.
 */
export declare const isValidEvent: (event: NostrEvent) => boolean;
//# sourceMappingURL=verify.d.ts.map