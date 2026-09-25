/**
 * nostr-bridge.js
 *
 * Injects window.nostr into any web page — supporting Web3Auth OAuth, NIP-46 bunkers (Alby,
 * Amber, nsec.app), and native extensions. The private key is held only in a sandboxed
 * cross-origin iframe and never accessible to parent page JS.
 *
 * PUBLIC API — Use standard NIP-07 calls:
 *
 *   window.nostr.getPublicKey()                     // returns hex pubkey
 *   window.nostr.signEvent(event)                   // returns signed event
 *   window.nostr.nip04?.encrypt(pubkey, plaintext) // returns ciphertext
 *   window.nostr.nip04?.decrypt(pubkey, ciphertext)// returns plaintext
 *   window.nostr.nip44?.encrypt(pubkey, plaintext) // returns ciphertext
 *   window.nostr.nip44?.decrypt(pubkey, ciphertext)// returns plaintext
 *
 * INITIALIZATION (required):
 *
 *   <script src="https://saintego.github.io/nostr-shard-signer/nostr-bridge.js"></script>
 *   <script>
 *     NostrBridge.init({
 *       clientId:       "YOUR_WEB3AUTH_CLIENT_ID",    // required; register it + your domain in the portal
 *       // Everything below is optional:
 *       bunkerOrigin:   "https://yourdomain.com/path",// self-hosted signer; defaults to the hosted one
 *       registrarUrl:   "https://registrar.example",  // defaults to the hosted registrar with the hosted signer
 *       forceIframe:    false,                        // skip native extensions if true
 *       layout:         "floating",                   // "floating" | "in-place"
 *       buttonSize:     "standard",                   // "standard" | "large_social_grid"
 *       mountSelector:  "#nostr-btn",                 // only used when layout === "in-place"
 *     });
 *   </script>
 *
 * Docs for AI coding agents: https://saintego.github.io/nostr-shard-signer/llms.txt
 * TypeScript types:          https://raw.githubusercontent.com/saintego/nostr-shard-signer/main/nostr-bridge.d.ts
 *
 * OPTIONAL: React to login/logout (listen for AUTH_STATE events):
 *
 *   window.addEventListener("message", (e) => {
 *     if (e.data?.type === "AUTH_STATE" && e.origin === "") {
 *       if (e.data.loggedIn) console.log("Logged in:", e.data.pubkey);
 *       else console.log("Logged out");
 *     }
 *   });
 *
 * OPTIONAL: React to setup errors (also logged to the console with a fix hint):
 *
 *   window.addEventListener("message", (e) => {
 *     if (e.data?.type === "SIGNER_ERROR" && e.origin === "") {
 *       console.log(e.data.code, e.data.message, e.data.hint);
 *     }
 *   });
 *
 * OPTIONAL BRIDGE METHODS (internal use, not typically needed):
 *   - NostrBridge.getSavedSession()   // Get cached session from localStorage
 *   - NostrBridge.getAuthState()      // Get current auth state
 *
 * Security notes:
 *  - The private key is held ONLY in a cross-origin iframe; Same-Origin Policy makes
 *    it unreachable from parent page JS, regardless of XSS attacks.
 *  - bunkerOrigin is validated on every postMessage.
 *  - event.source is checked against the specific iframe; "null" origins rejected.
 *  - Native extension probes have a 5-second timeout to prevent hanging.
 *  - Disconnect detection (Alby/WNJ): probed on tab focus regain via visibilitychange.
 */

(function (global) {
  "use strict";

  // ── Constants ─────────────────────────────────────────────────────────────────
  const EXTENSION_TIMEOUT_MS = 5000; // How long to wait for a native extension
  const RPC_TIMEOUT_MS = 30000; // How long to wait for an iframe RPC reply
  const IFRAME_AUTH_STATE_TIMEOUT_MS = 10000; // How long to wait for AUTH_STATE from iframe
  const IFRAME_ID = "nostr-signer-iframe";
  const CONTAINER_ID = "nostr-signer-container";
  const WNJ_STYLE_ID = "nostr-bridge-wnj-fix"; // style injected into WNJ's shadow root
  const MODE_IFRAME = "iframe"; // signing routed to the iframe bunker
  const MODE_WNJ = "wnj"; // signing routed to window.nostr.js signer

  // Hosted deployment, used when init() is called without bunkerOrigin.
  const DEFAULT_BUNKER_ORIGIN = "https://saintego.github.io/nostr-shard-signer";
  const DEFAULT_REGISTRAR_URL =
    "https://nostr-shard-registrar.nostr-shard-signer.workers.dev";
  const PORTAL_URL = "https://saintego.github.io/nostr-shard-signer/portal/";
  const DOCS_URL = "https://saintego.github.io/nostr-shard-signer/llms.txt";

  // Fix hints for SIGNER_ERROR codes sent by signer.html. They are logged in the
  // host page's console, which is where developers (and coding agents) look.
  const SIGNER_ERROR_HINTS = {
    DOMAIN_NOT_REGISTERED:
      "Register this page's origin for your clientId in the portal (" +
      PORTAL_URL +
      "), using the Update Domains tab if the clientId is already registered. " +
      "localhost cannot be registered. The registry lookup is cached per tab, so reload in a new tab afterwards.",
    WEB3AUTH_INIT_FAILED:
      "Check that clientId is your Web3Auth client ID and that the signer origin (" +
      "https://saintego.github.io for the hosted signer) is in the Web3Auth dashboard under " +
      "Project Settings → Domains → Allowlist URLs.",
    MISSING_ROOT_PUBKEY:
      "The signer could not load the registry key. With the hosted signer, omit bunkerOrigin and " +
      "registrarUrl so the defaults are used; a self-hosted signer needs a reachable registrarUrl.",
    NOT_EMBEDDED:
      "signer.html only works inside the iframe that nostr-bridge.js creates; do not open or embed it directly.",
  };

  // ── State ────────────────────────────────────────────────────────────────────
  let config = {};
  let iframeEl = null;
  let containerEl = null;
  let iframeReady = false; // true once iframe fires "load"
  let authStateTimer = null; // cleared when AUTH_STATE arrives
  let authState = "unknown"; // "unknown" | "loggedIn" | "loggedOut"
  let currentPubkey = null;
  let pendingQueue = []; // items waiting for AUTH_STATE to arrive
  let pendingRequests = {}; // id -> { resolve, reject, timer }
  let reqCounter = 0;
  let resolvedOrigin = null; // pinned after first valid message from iframe
  let initialized = false;
  let wnjNostr = null; // window.nostr.js implementation, captured after CDN load
  let wnjHostEl = null; // WNJ's shadow-host element, captured after CDN load
  let activeMode = MODE_IFRAME; // MODE_IFRAME | MODE_WNJ
  let sessionRestoreProtect = false; // true for one AUTH_STATE cycle after session restore
  let wnjDisconnectFn = null; // set inside init() when WNJ is loaded; callable from onMessage
  let signerError = null; // set when signer.html reports a setup error before AUTH_STATE
  let nativeNostrRef = null; // NIP-07 extension found on the page at init, if any
  let nativeWatchInstalled = false; // visibilitychange disconnect probe added

  // ── Session cache ─────────────────────────────────────────────────────────────
  // Persists the last successful login across page reloads so the UI immediately
  // shows the correct auth state instead of flashing the sign-in button.
  const SESSION_KEY = "nostr-bridge:session";
  function saveSession(pubkey, mode) {
    try {
      localStorage.setItem(
        SESSION_KEY,
        JSON.stringify({ pubkey: pubkey, mode: mode }),
      );
    } catch (_) {}
  }
  function clearSession() {
    try {
      localStorage.removeItem(SESSION_KEY);
    } catch (_) {}
  }
  function loadSession() {
    try {
      var s = localStorage.getItem(SESSION_KEY);
      return s ? JSON.parse(s) : null;
    } catch (_) {
      return null;
    }
  }

  // ── 2D size map [layout][state] ───────────────────────────────────────────────
  // Numeric values are converted to "Npx"; strings (e.g. "100%") are used as-is.
  const SIZE_MAP = {
    floating: {
      button: {
        // Single "Sign in" button — Web3Auth modal opens inside the iframe
        // Height hugs the ~40px button so the container's shadow outlines the
        // button itself rather than an empty box around it.
        standard: { w: 220, h: 56 },
        large_social_grid: { w: 220, h: 56 },
      },
      avatar: { w: 48, h: 48 },
      modal: { w: 420, h: 580 },
    },
    "in-place": {
      button: {
        standard: { w: "100%", h: "80px" },
        large_social_grid: { w: "100%", h: "80px" },
      },
      avatar: { w: "100%", h: "48px" },
      modal: { w: "100%", h: "580px" },
    },
  };

  // height (px) optionally overrides the modal height; the signer sends it when it
  // shows extra UI alongside Web3Auth's sheet and needs a taller iframe.
  function applySize(state, height) {
    if (!containerEl) return;
    const layout = config.layout === "in-place" ? "in-place" : "floating";
    const lmap = SIZE_MAP[layout];
    let dims;
    if (state === "button") {
      const bsMap = lmap.button;
      dims = bsMap[config.buttonSize] || bsMap.standard;
    } else {
      dims = lmap[state];
    }
    if (!dims) return;
    if (state === "modal" && height) dims = { w: dims.w, h: height };
    containerEl.style.width =
      typeof dims.w === "number" ? dims.w + "px" : dims.w;
    containerEl.style.height =
      typeof dims.h === "number" ? dims.h + "px" : dims.h;
  }

  // ── DOM helpers ──────────────────────────────────────────────────────────────
  function injectStyles() {
    if (document.getElementById("nostr-bridge-styles")) return;
    const style = document.createElement("style");
    style.id = "nostr-bridge-styles";
    const isFloating = config.layout !== "in-place";
    style.textContent = [
      "#" + CONTAINER_ID + " {",
      "  position: " + (isFloating ? "fixed" : "relative") + ";",
      isFloating
        ? "  bottom: calc(24px + env(safe-area-inset-bottom, 0px)); right: 24px;"
        : "",
      isFloating ? "  max-width: calc(100vw - 32px);" : "", // clamp on narrow screens
      isFloating ? "  max-height: calc(100vh - 32px);" : "", // ...and short ones
      "  z-index: 8999;", // below WNJ modal (9000) so WNJ always floats above
      "  transition: width 0.25s ease, height 0.25s ease;",
      "  overflow: hidden;",
      "  border: none;",
      "  background: transparent;",
      isFloating ? "  border-radius: 12px;" : "",
      isFloating ? "  box-shadow: 0 4px 24px rgba(0,0,0,0.18);" : "",
      "}",
      "#" + IFRAME_ID + " {",
      "  width: 100%; height: 100%;",
      "  border: none; background: transparent; display: block;",
      // The signer document is light-only. If the host page uses a dark
      // color-scheme, the iframe would inherit it and Chrome would paint an
      // opaque white backdrop behind the (transparent) signer, turning the
      // button into a white box. Matching schemes keeps the iframe transparent.
      "  color-scheme: normal;",
      "}",
    ].join("\n");
    document.head.appendChild(style);
  }

  function buildIframeSrc() {
    const base = config.bunkerOrigin.replace(/\/$/, "");
    const url = new URL(base + "/signer.html");
    url.searchParams.set("clientId", config.clientId);
    url.searchParams.set("layout", config.layout || "floating");
    url.searchParams.set("buttonSize", config.buttonSize || "standard");
    url.searchParams.set("parentOrigin", global.location.origin);
    if (config.registrarUrl) {
      url.searchParams.set("registrarUrl", config.registrarUrl);
    }
    // Tells the signer to offer a Nostr signer in its sign-in chooser; picking
    // it posts OPEN_NOSTR_SIGNER back so we open window.nostr.js or ask the
    // extension. "extension" changes the option's label.
    if (wnjNostr)
      url.searchParams.set(
        "nostrSigner",
        wnjNostr === nativeNostrRef ? "extension" : "1",
      );
    return url.toString();
  }

  function injectIframe() {
    if (document.getElementById(CONTAINER_ID)) return;

    injectStyles();

    containerEl = document.createElement("div");
    containerEl.id = CONTAINER_ID;
    // Start at the correct size for the current auth state so there is no
    // flash-of-button when a cached session is already set.
    applySize(authState === "loggedIn" ? "avatar" : "button");

    iframeEl = document.createElement("iframe");
    iframeEl.id = IFRAME_ID;
    iframeEl.src = buildIframeSrc();
    iframeEl.title = "Nostr Signer";

    // allow-same-origin: required so event.origin is not "null" inside the iframe.
    // allow-popups-to-escape-sandbox: required for Web3Auth's OAuth popup flow.
    // This means popups opened by the iframe inherit the iframe's origin context.
    iframeEl.setAttribute(
      "sandbox",
      "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-forms",
    );
    iframeEl.setAttribute("allow", "clipboard-write");
    iframeEl.setAttribute("referrerpolicy", "origin");

    // Guard RPC dispatch until the iframe document has finished loading
    iframeEl.addEventListener("load", function () {
      iframeReady = true;
    });

    containerEl.appendChild(iframeEl);

    if (config.layout === "in-place" && config.mountSelector) {
      const mount = document.querySelector(config.mountSelector);
      (mount || document.body).appendChild(containerEl);
    } else {
      document.body.appendChild(containerEl);
    }

    // WNJ mode: iframe is always shown; it will display the WNJ user's profile
    // once the bridge sends it a WNJ_SESSION message after AUTH_STATE arrives.
  }

  // ── postMessage helpers ──────────────────────────────────────────────────────
  function iframeWindow() {
    return iframeEl ? iframeEl.contentWindow : null;
  }

  function postToIframe(msg) {
    if (!iframeReady)
      throw new Error(
        "nostr-bridge: iframe not ready yet (was NostrBridge.init() called and the page body loaded?)",
      );
    const cw = iframeWindow();
    if (!cw) throw new Error("nostr-bridge: iframe not available");
    const target = resolvedOrigin || config.bunkerOrigin;
    cw.postMessage(msg, target);
  }

  // ── Incoming message handler ─────────────────────────────────────────────────
  function onMessage(event) {
    // Reject null origins unconditionally (sandboxed contexts without allow-same-origin)
    if (!event.origin || event.origin === "null") return;

    // Pin the origin on first contact; all future messages must match.
    // Use _bunkerMessageOrigin (bare scheme+host+port) because browsers strip
    // the path from event.origin even when the iframe URL includes one.
    if (!resolvedOrigin) {
      if (event.origin !== config._bunkerMessageOrigin) return;
      resolvedOrigin = event.origin;
    } else {
      if (event.origin !== resolvedOrigin) return;
    }

    // Source check: only messages from our specific iframe contentWindow
    if (event.source !== iframeWindow()) return;

    const data = event.data;
    if (!data || typeof data !== "object") return;

    // ── UI/State messages (custom schema) ────────────────────────────────────
    if (data.type === "AUTH_STATE") {
      if (authStateTimer) {
        clearTimeout(authStateTimer);
        authStateTimer = null;
      }
      // If WNJ mode is active and the iframe reports no session, that is expected —
      // the iframe's Web3Auth has no session but WNJ is still handling signing.
      // Do not let the iframe's bootstrap "not connected" override the WNJ session.
      if (!data.loggedIn && activeMode === MODE_WNJ) {
        // Iframe's Web3Auth has no session, but WNJ is handling signing.
        // Show the WNJ user's Nostr profile inside the iframe.
        const cw = iframeWindow();
        if (cw && currentPubkey) {
          cw.postMessage(
            { type: "WNJ_SESSION", pubkey: currentPubkey },
            config._bunkerMessageOrigin,
          );
        }
        applySize("avatar");
        flushQueue();
        return;
      }
      // While sessionRestoreProtect is set (MODE_IFRAME session restore pending),
      // block ALL AUTH_STATE:false from the iframe.  The flag is cleared by
      // AUTH_SUCCESS (session confirmed) or a timeout (session expired).
      // This prevents multiple Web3Auth bootstrap false-readings from flashing
      // the portal to disconnected before the iframe finishes initialising.
      if (
        sessionRestoreProtect &&
        !data.loggedIn &&
        activeMode === MODE_IFRAME
      ) {
        flushQueue();
        return; // keep flag; cleared by AUTH_SUCCESS handler or timeout
      }
      // If the iframe sends loggedIn:true while protection is active, clear it.
      if (sessionRestoreProtect && data.loggedIn) {
        sessionRestoreProtect = false;
      }
      authState = data.loggedIn ? "loggedIn" : "loggedOut";
      currentPubkey = data.pubkey || null;
      // Only reset activeMode when not in WNJ mode; WNJ routing must not be
      // overridden by the iframe echoing back its own loggedIn:true after
      // receiving a WNJ_SESSION message.
      if (activeMode !== MODE_WNJ) {
        activeMode = MODE_IFRAME; // reset; iframe auth-state change ends WNJ mode
        if (containerEl) containerEl.style.display = ""; // restore iframe if WNJ was hiding it
      }
      if (!data.loggedIn) clearSession(); // user logged out — clear cached session
      applySize(data.loggedIn ? "avatar" : "button"); // also controls WNJ button visibility
      // Notify the portal page so it can update its UI automatically.
      global.dispatchEvent(
        new MessageEvent("message", {
          data: {
            type: "AUTH_STATE",
            loggedIn: data.loggedIn,
            pubkey: data.pubkey || null,
          },
        }),
      );
      flushQueue();
      return;
    }

    if (data.type === "AUTH_SUCCESS") {
      if (authStateTimer) {
        clearTimeout(authStateTimer);
        authStateTimer = null;
      }
      sessionRestoreProtect = false; // iframe confirmed the session — stop blocking
      authState = "loggedIn";
      currentPubkey = data.pubkey;
      saveSession(data.pubkey, MODE_IFRAME);
      activeMode = MODE_IFRAME; // user authenticated via iframe OAuth
      applySize("avatar"); // also hides WNJ button
      flushQueue();
      // Notify the portal page so it can update its UI automatically.
      global.dispatchEvent(
        new MessageEvent("message", {
          data: { type: "AUTH_STATE", loggedIn: true, pubkey: data.pubkey },
        }),
      );
      return;
    }
    if (data.type === "WNJ_LOGOUT") {
      // Explicit user-initiated disconnect from the WNJ profile widget.
      // Bypass the pointer-presence check in _wnjDoDisconnect — the pointer
      // may still be present because the extension is still connected, but
      // the user explicitly chose to disconnect the profile.
      if (activeMode === MODE_WNJ) {
        activeMode = MODE_IFRAME;
        authState = "loggedOut";
        currentPubkey = null;
        clearSession();
        applySize("button");
        global.dispatchEvent(
          new MessageEvent("message", {
            data: { type: "AUTH_STATE", loggedIn: false, pubkey: null },
          }),
        );
      }
      // Tell the iframe to reset to login view.
      const cw = iframeWindow();
      if (cw)
        cw.postMessage({ type: "WNJ_DISCONNECT" }, config._bunkerMessageOrigin);
      return;
    }
    if (data.type === "OPEN_NOSTR_SIGNER") {
      // User picked "Nostr signer or bunker" in the signer's sign-in chooser.
      if (wnjNostr && activeMode !== MODE_WNJ) {
        wnjGetPublicKey().catch(function () {
          /* user cancelled */
        });
      }
      return;
    }
    if (data.type === "SIGNER_ERROR") {
      const code = typeof data.code === "string" ? data.code : "SIGNER_ERROR";
      const message = typeof data.message === "string" ? data.message : "";
      const hint = SIGNER_ERROR_HINTS[code] || "";
      console.error(
        "nostr-bridge: signer error " + code + ": " + message +
          (hint ? "\n→ " + hint : "") + "\nDocs: " + DOCS_URL,
      );
      if (code !== "LOGIN_FAILED") {
        signerError = "nostr-bridge: signer error " + code + ": " + message;
        // Setup failed before the iframe reported AUTH_STATE: fail queued calls
        // now with the real cause instead of after the AUTH_STATE timeout. Not
        // when window.nostr.js is loaded — users can still sign in through it.
        if (authState === "unknown" && !wnjNostr) {
          authState = "loggedOut";
          flushQueue();
        }
      }
      global.dispatchEvent(
        new MessageEvent("message", {
          data: { type: "SIGNER_ERROR", code: code, message: message, hint: hint },
        }),
      );
      return;
    }
    if (data.type === "RESIZE") {
      // Validate state before applying to prevent unexpected size changes
      if (!["button", "avatar", "modal"].includes(data.state)) return;
      // While session restore is pending, don't let the iframe's login view
      // shrink the container.  AUTH_STATE:false is already blocked by
      // sessionRestoreProtect; RESIZE:button must be blocked for the same
      // reason — otherwise the widget visually shows the login button while
      // the host app still shows the user as logged in (from savedSession).
      // The 10-second safety timer is responsible for the final transition.
      if (sessionRestoreProtect && data.state === "button") return;
      var height =
        typeof data.height === "number" && data.height >= 200 && data.height <= 1200
          ? Math.round(data.height)
          : undefined;
      applySize(data.state, height);
      return;
    }

    // ── NIP-46 RPC responses ─────────────────────────────────────────────────
    if (data.id !== undefined) {
      const pending = pendingRequests[data.id];
      if (!pending) return;
      clearTimeout(pending.timer);
      delete pendingRequests[data.id];
      data.error
        ? pending.reject(new Error(data.error))
        : pending.resolve(data.result);
    }
  }

  // Callers usually hit this by calling window.nostr before the user signed in,
  // so say how sign-in happens rather than just that it has not.
  function notLoggedInError() {
    return new Error(
      signerError ||
        "nostr-bridge: user is not logged in. The user signs in by clicking the " +
          "nostr-bridge widget's Sign in button; listen for the AUTH_STATE message " +
          "event to know when they have. Docs: " + DOCS_URL,
    );
  }

  // ── Queue management ─────────────────────────────────────────────────────────
  function flushQueue() {
    const queue = pendingQueue.splice(0);
    for (const item of queue) {
      if (authState === "loggedIn") {
        dispatchRpc(item.method, item.params)
          .then(item.resolve)
          .catch(item.reject);
      } else {
        item.reject(notLoggedInError());
      }
    }
  }

  // ── NIP-46 RPC dispatcher ────────────────────────────────────────────────────
  function dispatchRpc(method, params) {
    return new Promise(function (resolve, reject) {
      if (authState === "unknown") {
        // Queue: AUTH_STATE has not arrived yet
        pendingQueue.push({ method, params, resolve, reject });
        return;
      }
      if (authState === "loggedOut") {
        reject(notLoggedInError());
        return;
      }

      // Collision-resistant ID: monotonic counter + random suffix
      const id =
        "req_" + reqCounter++ + "_" + Math.random().toString(36).slice(2, 8);
      const timer = setTimeout(function () {
        delete pendingRequests[id];
        reject(
          new Error(
            "nostr-bridge: RPC timeout for '" + method + "' after " +
              RPC_TIMEOUT_MS / 1000 + "s (the user may not have answered the signer's confirmation prompt)",
          ),
        );
      }, RPC_TIMEOUT_MS);

      pendingRequests[id] = { resolve, reject, timer };

      try {
        postToIframe({ id, method, params });
      } catch (err) {
        clearTimeout(timer);
        delete pendingRequests[id];
        reject(err);
      }
    });
  }

  // ── window.nostr Proxy ───────────────────────────────────────────────────────
  // Routing priority:
  //   1. MODE_WNJ  — user already connected via window.nostr.js; delegate everything there.
  //   2. iframe loggedIn — user authenticated via OAuth; use cached pubkey / iframe RPC.
  //   3. wnjNostr available — try window.nostr.js first (shows its widget); on success
  //      lock activeMode = MODE_WNJ so all subsequent calls go through it. On failure
  //      (user cancelled or wnj not set up) fall through to iframe queue.
  //   4. iframe queue — authState unknown (still loading) or loggedOut.
  function wnjGetPublicKey() {
    // No z-index manipulation needed here: WNJ's modal (9000) sits above the
    // iframe container (8999). Because we never hide anything on click, a
    // cancelled WNJ flow (promise that never resolves) leaves the iframe widget
    // fully visible and clickable.
    return wnjNostr.getPublicKey().then(function (pubkey) {
      if (!pubkey) {
        // Some WNJ builds resolve with null/undefined on cancel.
        throw new Error(
          "nostr-bridge: WNJ returned no pubkey (user cancelled)",
        );
      }
      onSignerConnected(pubkey);
      return pubkey;
    });
  }

  // wnjNostr (window.nostr.js or an extension) returned a pubkey: route
  // signing to it, show the user's profile in the iframe widget, notify the page.
  function onSignerConnected(pubkey) {
    activeMode = MODE_WNJ;
    authState = "loggedIn";
    currentPubkey = pubkey;
    sessionRestoreProtect = false;
    saveSession(pubkey, MODE_WNJ);
    const cw = iframeWindow();
    if (cw) {
      cw.postMessage(
        { type: "WNJ_SESSION", pubkey: pubkey },
        config._bunkerMessageOrigin,
      );
    }
    if (wnjNostr === nativeNostrRef) watchNativeExtension();
    global.dispatchEvent(
      new MessageEvent("message", {
        data: { type: "AUTH_STATE", loggedIn: true, pubkey: pubkey },
      }),
    );
  }

  function buildNostrProxy() {
    return {
      getPublicKey() {
        if (activeMode === MODE_WNJ && wnjNostr) return wnjNostr.getPublicKey();
        if (authState === "loggedIn" && currentPubkey)
          return Promise.resolve(currentPubkey);
        // Try window.nostr.js first; fall back to iframe on rejection.
        // Skip WNJ after an explicit logout so callers reach the iframe login.
        if (wnjNostr && authState !== "loggedOut") {
          return wnjGetPublicKey().catch(function () {
            return dispatchRpc("get_public_key", []).then(function (result) {
              currentPubkey = result;
              return result;
            });
          });
        }
        return dispatchRpc("get_public_key", []).then(function (result) {
          currentPubkey = result;
          return result;
        });
      },

      signEvent(event) {
        if (activeMode === MODE_WNJ && wnjNostr)
          return wnjNostr.signEvent(event);
        return dispatchRpc("sign_event", [JSON.stringify(event)]).then(
          function (result) {
            return JSON.parse(result);
          },
        );
      },

      nip04: {
        encrypt(recipientHex, plaintext) {
          if (activeMode === MODE_WNJ && wnjNostr && wnjNostr.nip04)
            return wnjNostr.nip04.encrypt(recipientHex, plaintext);
          return dispatchRpc("nip04_encrypt", [recipientHex, plaintext]);
        },
        decrypt(senderHex, ciphertext) {
          if (activeMode === MODE_WNJ && wnjNostr && wnjNostr.nip04)
            return wnjNostr.nip04.decrypt(senderHex, ciphertext);
          return dispatchRpc("nip04_decrypt", [senderHex, ciphertext]);
        },
      },

      nip44: {
        encrypt(recipientHex, plaintext) {
          if (activeMode === MODE_WNJ && wnjNostr && wnjNostr.nip44)
            return wnjNostr.nip44.encrypt(recipientHex, plaintext);
          return dispatchRpc("nip44_encrypt", [recipientHex, plaintext]);
        },
        decrypt(senderHex, ciphertext) {
          if (activeMode === MODE_WNJ && wnjNostr && wnjNostr.nip44)
            return wnjNostr.nip44.decrypt(senderHex, ciphertext);
          return dispatchRpc("nip44_decrypt", [senderHex, ciphertext]);
        },
      },
    };
  }

  // ── window.nostr.js loader ────────────────────────────────────────────────────
  // Injects the CDN script, which installs itself as window.nostr.
  // We capture that implementation then reinstall our proxy on top.
  // Version is pinned and verified via SRI so a CDN compromise or silent upgrade
  // cannot execute arbitrary code in the parent page.
  const WNJ_SRC =
    "https://cdn.jsdelivr.net/npm/window.nostr.js@0.7.0/dist/window.nostr.min.js";
  const WNJ_INTEGRITY =
    "sha384-H2hej8dTR0r9VJj8VzmRwTasDnMUXXu5nJm7DSCNfMjgs23ZRgIJK3KCs5gOZ8OF";

  function loadWindowNostrJs() {
    return new Promise(function (resolve) {
      global.wnjParams = {
        startHidden: true, // portal login-btn is the single entry; WNJ opens programmatically
        accent: "purple",
      };
      var s = document.createElement("script");
      s.src = WNJ_SRC;
      s.integrity = WNJ_INTEGRITY;
      s.crossOrigin = "anonymous"; // required for SRI checks on cross-origin scripts
      s.onload = resolve;
      s.onerror = resolve; // silently degrade if CDN is unavailable or hash mismatch
      document.head.appendChild(s);
    });
  }

  // WNJ's connect panel has no max-height: on a short phone screen it grows
  // past the top edge (bottom-anchored), hiding the bunker input and close
  // button with no way to scroll. Cap it to the viewport and let it scroll.
  function injectWnjStyles() {
    var root = wnjHostEl && wnjHostEl.shadowRoot;
    if (!root || root.getElementById(WNJ_STYLE_ID)) return;
    var style = document.createElement("style");
    style.id = WNJ_STYLE_ID;
    style.textContent = [
      ".draggable > div {",
      "  max-height: calc(100vh - 16px);",
      "  max-height: calc(100dvh - 16px);",
      "  overflow-y: auto;",
      "  overscroll-behavior: contain;",
      "}",
    ].join("\n");
    root.appendChild(style);
  }

  // ── Native extension disconnect helper ──────────────────────────────────────
  function _nativeExtensionDisconnect() {
    if (activeMode !== MODE_WNJ) return;
    console.log(
      "[bridge] _nativeExtensionDisconnect: probe failed → loggedOut",
    );
    activeMode = MODE_IFRAME;
    authState = "loggedOut";
    currentPubkey = null;
    clearSession();
    applySize("button");
    var cwDisc = iframeWindow();
    if (cwDisc)
      cwDisc.postMessage(
        { type: "WNJ_DISCONNECT" },
        config._bunkerMessageOrigin,
      );
    global.dispatchEvent(
      new MessageEvent("message", {
        data: { type: "AUTH_STATE", loggedIn: false, pubkey: null },
      }),
    );
  }

  // Detect native extension disconnect (e.g. user locks/logs out of Alby).
  // On each tab focus, silently probe getPublicKey with a timeout.
  // If the probe fails or times out, send WNJ_DISCONNECT to the iframe.
  function watchNativeExtension() {
    if (nativeWatchInstalled) return;
    nativeWatchInstalled = true;
    let probeInFlight = false;
    global.document.addEventListener("visibilitychange", function () {
      if (global.document.visibilityState !== "visible") return;
      if (activeMode !== MODE_WNJ || probeInFlight) return;
      probeInFlight = true;
      const probeTimer = setTimeout(function () {
        probeInFlight = false;
        _nativeExtensionDisconnect();
      }, EXTENSION_TIMEOUT_MS);
      try {
        nativeNostrRef
          .getPublicKey()
          .then(function (pk) {
            clearTimeout(probeTimer);
            probeInFlight = false;
            if (!pk || pk !== currentPubkey) _nativeExtensionDisconnect();
          })
          .catch(function () {
            clearTimeout(probeTimer);
            probeInFlight = false;
            _nativeExtensionDisconnect();
          });
      } catch (_) {
        clearTimeout(probeTimer);
        probeInFlight = false;
        _nativeExtensionDisconnect();
      }
    });
  }

  // ── Native extension probe ───────────────────────────────────────────────────
  // Probes the pre-existing window.nostr (if any) with a timeout.
  // If the extension is installed but locked/unresponsive it will time out and
  // we fall through to injecting the iframe bunker. An extension that is only
  // waiting for the user to approve its prompt answers later: onLate gets that
  // pubkey.
  function probeNativeExtension(existingNostr, onLate) {
    return new Promise(function (resolve) {
      if (!existingNostr || typeof existingNostr.getPublicKey !== "function") {
        resolve(null);
        return;
      }
      let timedOut = false;
      const timer = setTimeout(function () {
        timedOut = true;
        resolve(null);
      }, EXTENSION_TIMEOUT_MS);
      try {
        existingNostr
          .getPublicKey()
          .then(function (pubkey) {
            clearTimeout(timer);
            const pk =
              typeof pubkey === "string" && pubkey.length > 0 ? pubkey : null;
            if (timedOut) {
              if (pk) onLate(pk);
              return;
            }
            // Return the pubkey so callers can dispatch AUTH_STATE without a
            // second getPublicKey() round-trip.
            resolve(pk);
          })
          .catch(function () {
            clearTimeout(timer);
            resolve(null);
          });
      } catch (_) {
        clearTimeout(timer);
        resolve(null);
      }
    });
  }

  // ── Public API ───────────────────────────────────────────────────────────────
  async function init(userConfig) {
    if (initialized) {
      console.warn("nostr-bridge: already initialized");
      return;
    }
    if (!userConfig || !userConfig.clientId) {
      throw new Error(
        "nostr-bridge: clientId is required. Use your Web3Auth client ID and register it " +
          "with this page's domain at " + PORTAL_URL,
      );
    }
    userConfig = Object.assign({}, userConfig);
    // With the hosted signer, the hosted registrar is the matching default: the
    // signer needs it to verify domain registrations.
    const bunkerOriginGiven = userConfig.bunkerOrigin || DEFAULT_BUNKER_ORIGIN;
    if (
      !userConfig.registrarUrl &&
      bunkerOriginGiven.replace(/\/$/, "") === DEFAULT_BUNKER_ORIGIN
    ) {
      userConfig.registrarUrl = DEFAULT_REGISTRAR_URL;
    }

    // Sanitize bunkerOrigin: keep origin + optional path, drop query/fragment.
    // This allows project-site hosting like /nostr-shard-signer on GitHub Pages.
    let bunkerUrl;
    try {
      bunkerUrl = new URL(bunkerOriginGiven);
    } catch (_) {
      throw new Error(
        "nostr-bridge: bunkerOrigin must be an absolute URL like " +
          DEFAULT_BUNKER_ORIGIN + " (got " + JSON.stringify(bunkerOriginGiven) +
          "). Omit it to use the hosted signer.",
      );
    }
    const normalizedPath =
      bunkerUrl.pathname === "/" ? "" : bunkerUrl.pathname.replace(/\/$/, "");
    const sanitizedOrigin = bunkerUrl.origin + normalizedPath;

    config = Object.assign(
      { layout: "floating", buttonSize: "standard", forceIframe: false },
      userConfig,
      {
        bunkerOrigin: sanitizedOrigin,
        // Browsers report event.origin as scheme+host+port only (no path).
        // Store the bare origin separately for postMessage origin validation.
        _bunkerMessageOrigin: bunkerUrl.origin,
      },
    );

    initialized = true;

    // ── Read saved session BEFORE any async work ─────────────────────────────
    // The iframe sends AUTH_STATE:false (which calls clearSession()) while WNJ
    // is still loading from the CDN.  Reading the session early and setting
    // sessionRestoreProtect immediately prevents the iframe's bootstrap false
    // from wiping the saved WNJ session before we can use it.
    const savedSession = loadSession();
    console.log("[bridge] savedSession:", savedSession);
    if (savedSession) {
      authState = "loggedIn";
      currentPubkey = savedSession.pubkey;
      // Use MODE_IFRAME as a placeholder until wnjNostr is determined below.
      // sessionRestoreProtect blocks the iframe's AUTH_STATE:false (and its
      // clearSession() call) for both IFRAME and WNJ saved sessions.
      activeMode = MODE_IFRAME;
      sessionRestoreProtect = true;
    }

    // Save a reference to any pre-existing window.nostr (native extension).
    // Do NOT install our proxy yet — window.nostr.js will refuse to set up
    // if it finds a non-WNJ object already occupying window.nostr.
    const nativeNostr =
      typeof global.nostr !== "undefined" ? global.nostr : null;

    // Register message listener before the iframe loads
    global.addEventListener("message", onMessage);

    if (!config.forceIframe && nativeNostr) {
      nativeNostrRef = nativeNostr;
      const nativePubkey = await probeNativeExtension(
        nativeNostr,
        function (latePubkey) {
          // The user approved the extension's prompt after the timeout. Don't
          // replace a login that happened in the meantime.
          if (authState === "loggedIn") return;
          console.info("nostr-bridge: extension answered late; signing in with it.");
          onSignerConnected(latePubkey);
          flushQueue();
        },
      );
      // The extension is the Nostr signer on offer either way: window.nostr.js
      // refuses to install next to it. If it didn't answer (locked, or waiting
      // for the user to approve), the sign-in chooser offers it, and picking
      // that asks the extension again.
      wnjNostr = nativeNostr;
      if (nativePubkey) {
        console.info(
          "nostr-bridge: native extension active; delegating signing to it, showing profile in iframe.",
        );
        // The iframe receives WNJ_SESSION when it boots and sends its
        // AUTH_STATE:false message.
        onSignerConnected(nativePubkey);
        flushQueue();
      } else {
        console.info(
          "nostr-bridge: extension did not answer within " +
            EXTENSION_TIMEOUT_MS / 1000 +
            "s; offering it in the sign-in chooser.",
        );
      }

      // Fall through — skip WNJ CDN load (wnjNostr already set) and inject iframe below.
    }

    if (!config.forceIframe && !wnjNostr) {
      // Load window.nostr.js — gives users a UI to connect Alby, Amber,
      // or any NIP-46 bunker via the floating widget.
      // window.nostr must be absent (or already WNJ) when the script runs;
      // if it finds a foreign object there it calls destroyWnj() and exits.
      await loadWindowNostrJs();
      // Detect WNJ by the isWnj sentinel it stamps on its own implementation.
      const afterLoad =
        typeof global.nostr !== "undefined" ? global.nostr : null;
      wnjNostr =
        afterLoad !== null && afterLoad.isWnj === true ? afterLoad : null;

      if (wnjNostr) {
        // Capture WNJ's shadow-host element so wnjGetPublicKey() can observe it.
        Array.prototype.some.call(document.body.children, function (el) {
          if (el.shadowRoot) {
            wnjHostEl = el;
            return true;
          }
        });
        injectWnjStyles();

        // Detect WNJ disconnect: WNJ v0.7.0 calls
        // localStorage.removeItem("wnj:bunkerPointer") when the user disconnects,
        // but ALSO calls removeItem then setItem during page-load reconnection
        // (e.g. restoring a saved NIP-46 bunker session on reload).
        //
        // Strategy: intercept both setItem and removeItem.
        //  • removeItem("wnj:bunkerPointer") → start a 3-second countdown
        //  • setItem("wnj:bunkerPointer", …) → cancel the countdown (WNJ reconnected)
        //  • After 3 s with no re-add → genuine disconnect → reset to iframe mode
        //
        // 3 seconds gives WNJ plenty of time for WebSocket setup and NIP-46
        // handshake even on slow connections, while still reacting promptly to
        // an explicit user-initiated logout.
        var _wnjDisconnectTimer = null;
        // Saved when _wnjDoDisconnect fires so a late setItem can recover the session.
        var _wnjLastKnownPubkey = null;

        var _wnjDoDisconnect = function () {
          _wnjDisconnectTimer = null;
          // Before treating this as a genuine disconnect, check whether WNJ has
          // already re-added the bunker pointer.  NIP-46 reconnects can take several
          // seconds (WebSocket + handshake); if the key is back, abort.
          var pointer = null;
          try {
            pointer = localStorage.getItem("wnj:bunkerPointer");
          } catch (_) {}
          // A non-null, non-empty pointer means WNJ reconnected. Empty string or null
          // means either truly disconnected or WNJ wrote a cleanup/empty value on logout.
          var hasRealPointer = pointer !== null && pointer.length > 2;
          console.log(
            "[bridge] _wnjDoDisconnect: pointer=%s hasReal=%s activeMode=%s",
            pointer,
            hasRealPointer,
            activeMode,
          );
          if (hasRealPointer) {
            console.log(
              "[bridge] _wnjDoDisconnect: valid pointer → reconnect detected, abort",
            );
            return; // WNJ reconnected — not a real disconnect
          }
          if (activeMode !== MODE_WNJ) return; // already handled elsewhere
          console.log(
            "[bridge] _wnjDoDisconnect: genuine disconnect → loggedOut",
          );
          _wnjLastKnownPubkey = currentPubkey; // remember for late-reconnect recovery
          activeMode = MODE_IFRAME;
          authState = "loggedOut";
          currentPubkey = null;
          clearSession();
          if (containerEl) containerEl.style.display = "";
          applySize("button");
          // Notify the iframe so it exits WNJ profile mode (resets to login view).
          var cwDisc = iframeWindow();
          if (cwDisc)
            cwDisc.postMessage(
              { type: "WNJ_DISCONNECT" },
              config._bunkerMessageOrigin,
            );
          global.dispatchEvent(
            new MessageEvent("message", {
              data: { type: "AUTH_STATE", loggedIn: false, pubkey: null },
            }),
          );
        };
        wnjDisconnectFn = _wnjDoDisconnect; // expose to outer scope for WNJ_LOGOUT handler

        // Auto-reconnect: if WNJ has a live bunker pointer but no bridge session
        // (e.g. the user previously clicked Disconnect in the profile modal,
        // which clears the bridge session without disconnecting the WNJ bunker),
        // call wnjGetPublicKey() silently — WNJ will resolve immediately since
        // it is already connected, and the iframe will receive WNJ_SESSION.
        if (!savedSession) {
          try {
            var wnjPointer = localStorage.getItem("wnj:bunkerPointer");
            if (wnjPointer && wnjPointer.length > 2) {
              console.log(
                "[bridge] WNJ bunker pointer found with no saved session — auto-reconnecting",
              );
              wnjGetPublicKey().catch(function () {
                /* ignore */
              });
            }
          } catch (_) {}
        }

        var _origSetItem = localStorage.setItem.bind(localStorage);
        localStorage.setItem = function (key, value) {
          _origSetItem(key, value);
          if (key === "wnj:bunkerPointer") {
            console.log(
              "[bridge] setItem wnj:bunkerPointer: timer=%s activeMode=%s lastPubkey=%s",
              _wnjDisconnectTimer,
              activeMode,
              _wnjLastKnownPubkey,
            );
            if (_wnjDisconnectTimer !== null) {
              // Only treat as a reconnect if the new value looks like a real bunker
              // connection (non-trivial JSON). WNJ may write an empty/cleanup string
              // during logout; cancelling on that would swallow the disconnect.
              if (value && value.length > 2) {
                console.log(
                  "[bridge] setItem: valid value → cancel pending disconnect (reconnect)",
                );
                clearTimeout(_wnjDisconnectTimer);
                _wnjDisconnectTimer = null;
              } else {
                console.log(
                  "[bridge] setItem: empty/short value → keep timer (logout cleanup write)",
                );
              }
            } else if (activeMode !== MODE_WNJ && _wnjLastKnownPubkey) {
              // The grace-period timer already fired before WNJ finished reconnecting.
              // WNJ is now connected — recover the session with the last known pubkey.
              console.log(
                "[bridge] setItem: late reconnect recovery, pubkey=%s",
                _wnjLastKnownPubkey,
              );
              var pubkey = _wnjLastKnownPubkey;
              _wnjLastKnownPubkey = null;
              activeMode = MODE_WNJ;
              authState = "loggedIn";
              currentPubkey = pubkey;
              saveSession(pubkey, MODE_WNJ);
              var cwRecover = iframeWindow();
              if (cwRecover) {
                cwRecover.postMessage(
                  { type: "WNJ_SESSION", pubkey: pubkey },
                  config._bunkerMessageOrigin,
                );
              }
              global.dispatchEvent(
                new MessageEvent("message", {
                  data: { type: "AUTH_STATE", loggedIn: true, pubkey: pubkey },
                }),
              );
            }
          }
        };

        var _origRemoveItem = localStorage.removeItem.bind(localStorage);
        localStorage.removeItem = function (key) {
          _origRemoveItem(key); // always perform the actual removal immediately
          if (key === "wnj:bunkerPointer") {
            console.log(
              "[bridge] removeItem wnj:bunkerPointer: activeMode=%s",
              activeMode,
            );
            if (activeMode === MODE_WNJ) {
              // Clear the bridge session NOW — before any async timer — so that if
              // the page is reloaded within the grace window the session is already
              // gone and the user won't be auto-reconnected.
              clearSession();
              // Cancel any existing timer (debounce rapid remove/re-add cycles).
              if (_wnjDisconnectTimer !== null)
                clearTimeout(_wnjDisconnectTimer);
              // 300 ms is enough time for WNJ to re-add the pointer if this is a
              // reconnect (WNJ reconnect fires setItem without removeItem, but we
              // keep a tiny window for edge cases).  300 ms also means logout UI
              // is nearly instant rather than the old 3–10 s delay.
              console.log(
                "[bridge] removeItem: session cleared; firing disconnect in 300ms",
              );
              _wnjDisconnectTimer = setTimeout(_wnjDoDisconnect, 300);
            }
          }
        };
      }
    }

    // Reinstall our proxy on top (locks window.nostr so nothing else overwrites it).
    const proxy = buildNostrProxy();
    try {
      Object.defineProperty(global, "nostr", {
        get() {
          return proxy;
        },
        set() {
          /* ignore */
        },
        configurable: true,
      });
    } catch (_) {
      global.nostr = proxy;
    }

    // ── Finalize saved-session restore now that wnjNostr is known ────────────
    if (savedSession) {
      // Determine the real mode — wnjNostr is now set (or null if unavailable).
      activeMode =
        savedSession.mode === MODE_WNJ && wnjNostr ? MODE_WNJ : MODE_IFRAME;
      console.log(
        "[bridge] finalize: savedMode=%s wnjNostr=%s → activeMode=%s",
        savedSession.mode,
        !!wnjNostr,
        activeMode,
      );

      if (activeMode === MODE_WNJ) {
        // WNJ is handling signing — iframe shows the WNJ user's profile.
        // WNJ_SESSION is sent when the iframe's AUTH_STATE:false arrives.
        sessionRestoreProtect = false; // no AUTH_SUCCESS expected from iframe
        console.log(
          "[bridge] WNJ mode: wnj:bunkerPointer in storage =",
          localStorage.getItem("wnj:bunkerPointer"),
        );
      } else {
        // IFRAME mode: keep sessionRestoreProtect to block the iframe's initial
        // AUTH_STATE:false while Web3Auth restores its own session in the background.
        // Safety net: if AUTH_SUCCESS never arrives (session truly expired),
        // expire the protection and notify the portal as disconnected.
        setTimeout(function () {
          if (!sessionRestoreProtect) return; // already cleared by AUTH_SUCCESS
          sessionRestoreProtect = false;
          authState = "loggedOut";
          currentPubkey = null;
          clearSession();
          applySize("button");
          global.dispatchEvent(
            new MessageEvent("message", {
              data: { type: "AUTH_STATE", loggedIn: false, pubkey: null },
            }),
          );
        }, IFRAME_AUTH_STATE_TIMEOUT_MS);
      }

      // Notify the portal so it shows the connected state on reload.
      global.dispatchEvent(
        new MessageEvent("message", {
          data: {
            type: "AUTH_STATE",
            loggedIn: true,
            pubkey: savedSession.pubkey,
          },
        }),
      );
      flushQueue();
    }

    // AUTH_STATE timeout: if the iframe doesn't report back in time,
    // flush the pending queue as logged-out to unblock callers.
    authStateTimer = setTimeout(function () {
      if (authState === "unknown") {
        authState = "loggedOut";
        flushQueue();
      }
    }, IFRAME_AUTH_STATE_TIMEOUT_MS);

    // Inject iframe (deferred if DOM not ready yet)
    if (document.body) {
      injectIframe();
    } else {
      document.addEventListener("DOMContentLoaded", injectIframe);
    }
  }

  // ── Expose ───────────────────────────────────────────────────────────────────
  global.NostrBridge = {
    init,
    // Returns the current auth state synchronously.  Portals can call this
    // after awaiting init() as a fallback when the session-restore dispatch
    // fires before their message listener is attached.
    getAuthState() {
      return { loggedIn: authState === "loggedIn", pubkey: currentPubkey };
    },
    // Returns the saved session from localStorage synchronously — callable before
    // init() resolves so portals can pre-render the connected state immediately.
    getSavedSession: loadSession,
  };
})(window);
