/**
 * nostr-shard-signer: types and loader for nostr-bridge.js.
 *
 *   import { loadNostrBridge } from "nostr-shard-signer";
 *   const NostrBridge = await loadNostrBridge({ clientId: "YOUR_WEB3AUTH_CLIENT_ID" });
 *   NostrBridge.onAuthChange(({ loggedIn, pubkey }) => { ... });
 *
 * To type `window.nostr` as the bridge's signer, also add
 * `/// <reference types="nostr-shard-signer/window" />`.
 */

import type { NostrBridgeApi, NostrBridgeConfig } from "./nostr-bridge.js";

export type {
  NostrUnsignedEvent,
  NostrSignedEvent,
  NostrBridgeSigner,
  NostrBridgeConfig,
  NostrBridgeAuthState,
  NostrBridgeSavedSession,
  NostrBridgeApi,
  NostrBridgeEvent,
} from "./nostr-bridge.js";

/** NostrBridge.apiVersion that these types describe. */
export declare const API_VERSION: 1;

/**
 * Loads nostr-bridge.js from `<bunkerOrigin>/nostr-bridge.js` (the hosted
 * signer by default), so the bridge always matches its signer, then calls
 * `NostrBridge.init(config)`. Resolves with `NostrBridge` once `window.nostr`
 * is installed. Safe to call more than once; later calls keep the first
 * config. Browser only: it rejects when there is no `window`. Rejects if the
 * script can't be loaded; a later call retries.
 */
export declare function loadNostrBridge(config?: NostrBridgeConfig): Promise<NostrBridgeApi>;
