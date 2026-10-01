/**
 * Type declarations for nostr-bridge.js
 * https://saintego.github.io/nostr-shard-signer/nostr-bridge.js
 *
 * nostr-bridge.js is a classic script (not an ES module): load it with a
 * <script> tag and it defines the globals below. To get these types, copy this
 * file into your project, or reference it:
 *
 *   /// <reference path="./nostr-bridge.d.ts" />
 *
 * The interfaces are global, and can also be imported by name:
 *
 *   import type { NostrBridgeConfig, NostrBridgeAuthState } from "./nostr-bridge";
 *
 * This file does not type `window.nostr`, so it coexists with other NIP-07
 * declarations. To type `window.nostr` as the bridge's signer, also include
 * nostr-bridge-window.d.ts.
 *
 * Docs for AI coding agents: https://saintego.github.io/nostr-shard-signer/llms.txt
 */

export type NostrUnsignedEvent = globalThis.NostrUnsignedEvent;
export type NostrSignedEvent = globalThis.NostrSignedEvent;
export type NostrBridgeSigner = globalThis.NostrBridgeSigner;
export type NostrBridgeConfig = globalThis.NostrBridgeConfig;
export type NostrBridgeAuthState = globalThis.NostrBridgeAuthState;
export type NostrBridgeSavedSession = globalThis.NostrBridgeSavedSession;
export type NostrBridgeApi = globalThis.NostrBridgeApi;
export type NostrBridgeEvent = globalThis.NostrBridgeEvent;

declare global {
  /** Unsigned Nostr event (NIP-01) as passed to `window.nostr.signEvent`. */
  interface NostrUnsignedEvent {
    kind: number;
    created_at: number;
    tags: string[][];
    content: string;
    /** Ignored; the signer always uses the logged-in user's pubkey. */
    pubkey?: string;
  }

  /** Signed Nostr event returned by `window.nostr.signEvent`. */
  interface NostrSignedEvent extends NostrUnsignedEvent {
    id: string;
    pubkey: string;
    sig: string;
  }

  /**
   * Standard NIP-07 signer, installed on `window.nostr` by `NostrBridge.init()`.
   *
   * Calls made before the signer iframe has reported its auth state are queued.
   * If the user is not logged in, calls reject with an Error whose message starts
   * with "nostr-bridge: user is not logged in". Don't rely on these calls to
   * prompt a login: the user signs in with the bridge widget's "Sign in" button,
   * or your own button calling `NostrBridge.login()`. Use
   * `NostrBridge.onAuthChange` to know when that happens.
   */
  interface NostrBridgeSigner {
    /** Returns the user's public key as 64-char lowercase hex (not npub). */
    getPublicKey(): Promise<string>;
    /**
     * Signs an event. With Web3Auth login, kinds 1 and 7 are auto-approved by
     * default and other kinds show a confirmation prompt inside the signer
     * (extensions and bunkers apply their own rules). Rejects after 30 s
     * without an answer.
     */
    signEvent(event: NostrUnsignedEvent): Promise<NostrSignedEvent>;
    /** NIP-04 encryption (legacy DMs). Both methods show a confirmation prompt with Web3Auth login. */
    nip04: {
      encrypt(recipientPubkeyHex: string, plaintext: string): Promise<string>;
      decrypt(senderPubkeyHex: string, ciphertext: string): Promise<string>;
    };
    /** NIP-44 encryption. Decrypt shows a confirmation prompt with Web3Auth login. */
    nip44: {
      encrypt(recipientPubkeyHex: string, plaintext: string): Promise<string>;
      decrypt(senderPubkeyHex: string, ciphertext: string): Promise<string>;
    };
  }

  interface NostrBridgeConfig {
    /**
     * Your Web3Auth client ID. Optional: without it, users sign in only with a
     * NIP-07 extension or a NIP-46 bunker. With it, Google/Apple/X sign-in works
     * on origins registered for it in the portal or listed in the project's
     * Allowlist URLs in the Web3Auth dashboard (which must also list
     * https://saintego.github.io).
     */
    clientId?: string;
    /**
     * Base URL where signer.html is hosted. Defaults to the hosted signer,
     * "https://saintego.github.io/nostr-shard-signer". Only set it when you
     * self-host the signer.
     */
    bunkerOrigin?: string;
    /**
     * Registrar Worker URL the signer uses to find the registry key. Defaults to
     * the hosted registrar when `bunkerOrigin` is the hosted signer.
     */
    registrarUrl?: string;
    /**
     * Skip the installed NIP-07 extension (Alby, nos2x…) and window.nostr.js,
     * and always use the Web3Auth iframe. Default false. Ignored without clientId.
     */
    forceIframe?: boolean;
    /**
     * "floating" (default): fixed widget in the bottom-right corner.
     * "in-place": widget rendered inside `mountSelector`.
     */
    layout?: "floating" | "in-place";
    /** Default "standard". */
    buttonSize?: "standard" | "large_social_grid";
    /** CSS selector of the element to render into when layout is "in-place". Falls back to <body>. */
    mountSelector?: string;
  }

  interface NostrBridgeAuthState {
    loggedIn: boolean;
    /** Hex pubkey, or null when logged out. */
    pubkey: string | null;
  }

  interface NostrBridgeSavedSession {
    pubkey: string;
    /** "iframe" = Web3Auth login, "wnj" = NIP-07 extension or NIP-46 bunker. */
    mode: "iframe" | "wnj";
  }

  interface NostrBridgeApi {
    /**
     * Installs `window.nostr` and injects the signer widget. Safe to call more
     * than once (React StrictMode, remounts, after data-client-id auto-init):
     * later calls return the first call's promise and ignore their config.
     * Rejects if bunkerOrigin is not a valid URL; a corrected call may then retry. Await it before reading `window.nostr`.
     */
    init(config?: NostrBridgeConfig): Promise<void>;
    /** Resolves once init() has completed, however it was called. */
    readonly ready: Promise<void>;
    /**
     * Calls `callback` on every login/logout. If the auth state is already known,
     * it is also called right away with the current state, so a session restored
     * before subscribing is not missed. Returns an unsubscribe function.
     * Same data as the "nostr-bridge:auth" window event.
     */
    onAuthChange(callback: (state: NostrBridgeAuthState) => void): () => void;
    /**
     * Opens the signer's sign-in modal, like the widget's "Sign in" button, so
     * apps can use their own login button. Resolves once the modal was requested
     * (immediately if already logged in); `onAuthChange` reports the outcome.
     * Rejects if init() was never called.
     */
    login(): Promise<void>;
    /** Signs the user out. Resolves once the logged-out state is reported. */
    logout(): Promise<void>;
    /** Current auth state, synchronously. */
    getAuthState(): NostrBridgeAuthState;
    /** Session cached in localStorage from a previous visit, callable before init(). */
    getSavedSession(): NostrBridgeSavedSession | null;
  }

  /**
   * Legacy form of the auth/error notifications; prefer `NostrBridge.onAuthChange`
   * or the "nostr-bridge:auth" event for auth changes.
   * Events the bridge dispatches on `window` as MessageEvents with
   * `event.origin === ""` (no real sender). Check the origin so other
   * postMessage traffic can't fake them:
   *
   *   window.addEventListener("message", (e) => {
   *     if (e.origin !== "" || e.data?.type !== "AUTH_STATE") return;
   *     ...
   *   });
   */
  type NostrBridgeEvent =
    | { type: "AUTH_STATE"; loggedIn: boolean; pubkey: string | null }
    | {
        type: "SIGNER_ERROR";
        /**
         * CLIENT_ID_NOT_FOUND | DOMAIN_NOT_REGISTERED |
         * WEB3AUTH_INIT_FAILED | MISSING_ROOT_PUBKEY | NO_SIGN_IN_METHOD |
         * NOT_EMBEDDED | INIT_ERROR | LOGIN_FAILED
         */
        code: string;
        message: string;
        /** How to fix it; empty for codes without a known fix. */
        hint: string;
      };

  interface WindowEventMap {
    /** Fired on `window` when the user logs in or out. */
    "nostr-bridge:auth": CustomEvent<NostrBridgeAuthState>;
  }

  var NostrBridge: NostrBridgeApi;
}
