/**
 * Opt-in: types `window.nostr` as the signer nostr-bridge.js installs.
 *
 * Kept apart from nostr-bridge.d.ts because another library that declares
 * `window.nostr` with its own NIP-07 type can't be combined with this one
 * (TypeScript: "Subsequent property declarations must have the same type").
 * Include this file only if nothing else in your project declares `window.nostr`.
 *
 *   /// <reference path="./nostr-bridge-window.d.ts" />
 */

/// <reference path="./nostr-bridge.d.ts" />

export {};

declare global {
  interface Window {
    nostr: NostrBridgeSigner;
  }
}
