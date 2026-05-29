/**
 * nostr-bridge.js
 *
 * Parent wrapper that injects the cross-origin iframe bunker and proxies
 * window.nostr calls via NIP-46 RPC over postMessage.
 *
 * Usage:
 *   <script src="nostr-bridge.js"></script>
 *   <script>
 *     NostrBridge.init({
 *       clientId:     "YOUR_WEB3AUTH_CLIENT_ID",
 *       bunkerOrigin: "https://bunker.yourdomain.com",   // required
 *       forceIframe:  false,
 *       layout:       "floating",      // "floating" | "in-place"
 *       buttonSize:   "standard",      // "standard" | "large_social_grid"
 *       mountSelector: "#nostr-btn",   // only used when layout === "in-place"
 *     });
 *   </script>
 *
 * Security notes:
 *  - bunkerOrigin is required and sanitized to its bare origin (no path/query).
 *  - All postMessage calls target the pinned bunkerOrigin exactly (no wildcard).
 *  - event.source is checked against the specific iframe contentWindow.
 *  - "null" origins are rejected unconditionally.
 *  - A 5-second probe timeout prevents locked extensions from hanging the queue.
 *  - AUTH_STATE is expected within 10 s; pending queue is flushed as logged-out otherwise.
 */

(function (global) {
  "use strict";

  // ── Constants ─────────────────────────────────────────────────────────────────
  const EXTENSION_TIMEOUT_MS = 5000; // How long to wait for a native extension
  const RPC_TIMEOUT_MS = 30000; // How long to wait for an iframe RPC reply
  const IFRAME_AUTH_STATE_TIMEOUT_MS = 10000; // How long to wait for AUTH_STATE from iframe
  const IFRAME_ID = "nostr-signer-iframe";
  const CONTAINER_ID = "nostr-signer-container";
  const WNJ_BTN_ID = "nostr-wnj-btn"; // trigger button injected below the iframe when WNJ is available
  const MODE_IFRAME = "iframe"; // signing routed to the iframe bunker
  const MODE_WNJ = "wnj"; // signing routed to window.nostr.js signer

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
        standard: { w: 220, h: 80 },
        large_social_grid: { w: 220, h: 80 },
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

  function applySize(state) {
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
    containerEl.style.width =
      typeof dims.w === "number" ? dims.w + "px" : dims.w;
    containerEl.style.height =
      typeof dims.h === "number" ? dims.h + "px" : dims.h;
    // WNJ trigger is only shown while the sign-in modal is open AND the user
    // is not already logged in (so it never shows when the profile modal opens).
    var wnjBtnEl = document.getElementById(WNJ_BTN_ID);
    if (wnjBtnEl)
      wnjBtnEl.style.display =
        state === "modal" && authState !== "loggedIn" ? "" : "none";
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
        ? "  bottom: " + (wnjNostr ? "72px" : "24px") + "; right: 24px;"
        : "",
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

    // If WNJ is available, inject a trigger button below the iframe widget.
    // WNJ startHidden=true suppresses its own floating button; this button
    // is the visible entry point that stacks below the iframe button.
    if (wnjNostr && config.layout !== "in-place") {
      var wnjBtnEl = document.createElement("button");
      wnjBtnEl.id = WNJ_BTN_ID;
      wnjBtnEl.style.cssText = [
        "position:fixed",
        "bottom:24px",
        "right:24px",
        "width:220px",
        "height:40px",
        "border:none",
        "border-radius:8px",
        "background:#1a1033",
        "color:#fff",
        "font-size:13px",
        "font-family:system-ui,sans-serif",
        "cursor:pointer",
        "z-index:8998", // below iframe (8999) and WNJ modal (9000)
        "box-shadow:0 4px 24px rgba(0,0,0,0.18)",
        "display:none",
      ].join(";");
      wnjBtnEl.textContent = "Sign in with Extension or Bunker";
      wnjBtnEl.addEventListener("click", function () {
        wnjGetPublicKey().catch(function () {
          /* user cancelled */
        });
      });
      document.body.appendChild(wnjBtnEl);
    }

    // In WNJ mode (restored from session cache), keep the iframe hidden —
    // WNJ handles all signing, so the OAuth iframe widget should not be visible.
    if (activeMode === MODE_WNJ) {
      containerEl.style.display = "none";
    }
  }

  // ── postMessage helpers ──────────────────────────────────────────────────────
  function iframeWindow() {
    return iframeEl ? iframeEl.contentWindow : null;
  }

  function postToIframe(msg) {
    if (!iframeReady) throw new Error("nostr-bridge: iframe not ready yet");
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
      activeMode = MODE_IFRAME; // reset; iframe auth-state change ends WNJ mode
      if (containerEl) containerEl.style.display = ""; // restore iframe if WNJ was hiding it
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

    if (data.type === "RESIZE") {
      // Validate state before applying to prevent unexpected size changes
      if (!["button", "avatar", "modal"].includes(data.state)) return;
      applySize(data.state);
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

  // ── Queue management ─────────────────────────────────────────────────────────
  function flushQueue() {
    const queue = pendingQueue.splice(0);
    for (const item of queue) {
      if (authState === "loggedIn") {
        dispatchRpc(item.method, item.params)
          .then(item.resolve)
          .catch(item.reject);
      } else {
        item.reject(new Error("nostr-bridge: user is not logged in"));
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
        reject(new Error("nostr-bridge: user is not logged in"));
        return;
      }

      // Collision-resistant ID: monotonic counter + random suffix
      const id =
        "req_" + reqCounter++ + "_" + Math.random().toString(36).slice(2, 8);
      const timer = setTimeout(function () {
        delete pendingRequests[id];
        reject(new Error("nostr-bridge: RPC timeout for '" + method + "'"));
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
    // No z-index manipulation needed here: the CSS already establishes the
    // correct stacking order for all three layers:
    //   WNJ modal (90000)  >  iframe container (89999)  >  WNJ button (89998)
    // WNJ's modal therefore always floats above both without any JS intervention.
    // Because we never hide anything on click, a cancelled WNJ flow (promise
    // that never resolves) leaves both the iframe widget and the WNJ button
    // fully visible and clickable.
    var wnjBtnEl = document.getElementById(WNJ_BTN_ID);

    return wnjNostr.getPublicKey().then(function (pubkey) {
      if (!pubkey) {
        // Some WNJ builds resolve with null/undefined on cancel.
        throw new Error(
          "nostr-bridge: WNJ returned no pubkey (user cancelled)",
        );
      }
      activeMode = MODE_WNJ;
      authState = "loggedIn";
      currentPubkey = pubkey;
      saveSession(pubkey, MODE_WNJ);
      // WNJ connected: hide the OAuth iframe widget — WNJ handles signing now.
      if (containerEl) containerEl.style.display = "none";
      if (wnjBtnEl) wnjBtnEl.style.display = "none";
      // Notify the portal page.
      global.dispatchEvent(
        new MessageEvent("message", {
          data: { type: "AUTH_STATE", loggedIn: true, pubkey: pubkey },
        }),
      );
      return pubkey;
    });
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

  // ── Native extension probe ───────────────────────────────────────────────────
  // Probes the pre-existing window.nostr (if any) with a timeout.
  // If the extension is installed but locked/unresponsive it will time out and
  // we fall through to injecting the iframe bunker.
  function probeNativeExtension(existingNostr) {
    return new Promise(function (resolve) {
      if (!existingNostr || typeof existingNostr.getPublicKey !== "function") {
        resolve(false);
        return;
      }
      const timer = setTimeout(function () {
        resolve(false);
      }, EXTENSION_TIMEOUT_MS);
      try {
        existingNostr
          .getPublicKey()
          .then(function () {
            clearTimeout(timer);
            resolve(true);
          })
          .catch(function () {
            clearTimeout(timer);
            resolve(false);
          });
      } catch (_) {
        clearTimeout(timer);
        resolve(false);
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
      throw new Error("nostr-bridge: clientId is required");
    }
    if (!userConfig.bunkerOrigin) {
      throw new Error("nostr-bridge: bunkerOrigin is required");
    }

    // Sanitize bunkerOrigin: keep origin + optional path, drop query/fragment.
    // This allows project-site hosting like /nostr-shard-signer on GitHub Pages.
    const bunkerUrl = new URL(userConfig.bunkerOrigin);
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

    // Save a reference to any pre-existing window.nostr (native extension).
    // Do NOT install our proxy yet — window.nostr.js will refuse to set up
    // if it finds a non-WNJ object already occupying window.nostr.
    const nativeNostr =
      typeof global.nostr !== "undefined" ? global.nostr : null;

    // Register message listener before the iframe loads
    global.addEventListener("message", onMessage);

    if (!config.forceIframe && nativeNostr) {
      const works = await probeNativeExtension(nativeNostr);
      if (works) {
        // The native extension is responsive — keep it and skip everything.
        global.removeEventListener("message", onMessage);
        initialized = false;
        console.info(
          "nostr-bridge: responsive native extension found; iframe skipped.",
        );
        return;
      }
    }

    if (!config.forceIframe) {
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

        // Detect WNJ disconnect: WNJ v0.7.0 always calls
        // localStorage.removeItem("wnj:bunkerPointer") when the user disconnects.
        // We delay the disconnect handling by 500 ms because WNJ may remove and
        // immediately re-add the pointer during reconnection (e.g. on page load
        // while restoring a saved bunker session).  Only treat the absence as a
        // genuine disconnect if the pointer is still gone after the delay.
        var _origRemoveItem = localStorage.removeItem.bind(localStorage);
        localStorage.removeItem = function (key) {
          _origRemoveItem(key); // always perform the actual removal immediately
          if (key === "wnj:bunkerPointer" && activeMode === MODE_WNJ) {
            setTimeout(function () {
              try {
                if (localStorage.getItem("wnj:bunkerPointer") !== null) return; // re-added: reconnect, not disconnect
              } catch (_) {}
              if (activeMode !== MODE_WNJ) return; // already switched elsewhere
              activeMode = MODE_IFRAME;
              authState = "loggedOut";
              currentPubkey = null;
              clearSession();
              if (containerEl) containerEl.style.display = "";
              applySize("button");
              // Notify the portal that the user signed out via WNJ.
              global.dispatchEvent(
                new MessageEvent("message", {
                  data: { type: "AUTH_STATE", loggedIn: false, pubkey: null },
                }),
              );
            }, 500);
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

    // Restore last session from localStorage — pre-seeds auth state so the UI
    // immediately shows the correct state on reload (no flash of sign-in button).
    const savedSession = loadSession();
    if (savedSession) {
      authState = "loggedIn";
      currentPubkey = savedSession.pubkey;
      activeMode =
        savedSession.mode === MODE_WNJ && wnjNostr ? MODE_WNJ : MODE_IFRAME;
      // For iframe-mode sessions, guard the restored state against the iframe's
      // initial AUTH_STATE:false (Web3Auth still loading its own session).
      if (activeMode === MODE_IFRAME) {
        // Block ALL false from iframe until AUTH_SUCCESS confirms the session.
        sessionRestoreProtect = true;
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
      // Notify the portal immediately so it shows the connected state on reload.
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
