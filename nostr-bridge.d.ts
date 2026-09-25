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
 * Docs for AI coding agents: https://saintego.github.io/nostr-shard-signer/llms.txt
 */

export {};

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
   * prompt a login: the user signs in by clicking the bridge widget's "Sign in"
   * button. Watch for the AUTH_STATE message event to know when that happens.
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
     * Your Web3Auth client ID. Required. It must be registered together with the
     * page's origin in the portal: https://saintego.github.io/nostr-shard-signer/portal/
     */
    clientId: string;
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
     * and always use the Web3Auth iframe. Default false.
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
     * Installs `window.nostr` and injects the signer widget. Call once per page;
     * later calls log a warning and do nothing. Throws if clientId is missing or
     * bunkerOrigin is not a valid URL. Await it before reading `window.nostr`.
     */
    init(config: NostrBridgeConfig): Promise<void>;
    /** Current auth state, synchronously. */
    getAuthState(): NostrBridgeAuthState;
    /** Session cached in localStorage from a previous visit, callable before init(). */
    getSavedSession(): NostrBridgeSavedSession | null;
  }

  /**
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
         * DOMAIN_NOT_REGISTERED | WEB3AUTH_INIT_FAILED | MISSING_ROOT_PUBKEY |
         * NOT_EMBEDDED | MISSING_CLIENT_ID | INIT_ERROR | LOGIN_FAILED
         */
        code: string;
        message: string;
        /** How to fix it; empty for codes without a known fix. */
        hint: string;
      };

  interface Window {
    NostrBridge: NostrBridgeApi;
    nostr: NostrBridgeSigner;
  }

  var NostrBridge: NostrBridgeApi;
}
