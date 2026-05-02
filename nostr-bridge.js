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

  // ── 2D size map [layout][state] ───────────────────────────────────────────────
  // Numeric values are converted to "Npx"; strings (e.g. "100%") are used as-is.
  const SIZE_MAP = {
    floating: {
      button: {
        standard: { w: 220, h: 48 },
        large_social_grid: { w: 320, h: 136 },
      },
      avatar: { w: 48, h: 48 },
      modal: { w: 420, h: 580 },
    },
    "in-place": {
      button: {
        standard: { w: "100%", h: "48px" },
        large_social_grid: { w: "100%", h: "136px" },
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
      isFloating ? "  bottom: 24px; right: 24px;" : "",
      "  z-index: 2147483647;",
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
    return url.toString();
  }

  function injectIframe() {
    if (document.getElementById(CONTAINER_ID)) return;

    injectStyles();

    containerEl = document.createElement("div");
    containerEl.id = CONTAINER_ID;
    applySize("button");

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
    // Prevent iframe from navigating the parent page
    iframeEl.setAttribute("csp", "default-src 'self'");

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

    // Pin the origin on first contact; all future messages must match
    if (!resolvedOrigin) {
      if (event.origin !== config.bunkerOrigin) return;
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
      authState = data.loggedIn ? "loggedIn" : "loggedOut";
      currentPubkey = data.pubkey || null;
      applySize(data.loggedIn ? "avatar" : "button");
      flushQueue();
      return;
    }

    if (data.type === "AUTH_SUCCESS") {
      if (authStateTimer) {
        clearTimeout(authStateTimer);
        authStateTimer = null;
      }
      authState = "loggedIn";
      currentPubkey = data.pubkey;
      applySize("avatar");
      flushQueue();
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
  function buildNostrProxy() {
    return {
      getPublicKey() {
        if (authState === "loggedIn" && currentPubkey) {
          return Promise.resolve(currentPubkey);
        }
        return dispatchRpc("get_public_key", []).then(function (result) {
          currentPubkey = result;
          return result;
        });
      },

      signEvent(event) {
        return dispatchRpc("sign_event", [JSON.stringify(event)]).then(
          function (result) {
            return JSON.parse(result);
          },
        );
      },

      nip04: {
        encrypt(recipientHex, plaintext) {
          return dispatchRpc("nip04_encrypt", [recipientHex, plaintext]);
        },
        decrypt(senderHex, ciphertext) {
          return dispatchRpc("nip04_decrypt", [senderHex, ciphertext]);
        },
      },

      nip44: {
        encrypt(recipientHex, plaintext) {
          return dispatchRpc("nip44_encrypt", [recipientHex, plaintext]);
        },
        decrypt(senderHex, ciphertext) {
          return dispatchRpc("nip44_decrypt", [senderHex, ciphertext]);
        },
      },
    };
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

    // Sanitize bunkerOrigin: strip any path/query/fragment to prevent injection
    const sanitizedOrigin = new URL(userConfig.bunkerOrigin).origin;

    config = Object.assign(
      { layout: "floating", buttonSize: "standard", forceIframe: false },
      userConfig,
      { bunkerOrigin: sanitizedOrigin },
    );

    initialized = true;

    // Save a reference to any pre-existing window.nostr (native extension)
    const nativeNostr =
      typeof global.nostr !== "undefined" ? global.nostr : null;

    // Install our proxy synchronously so callers can queue immediately.
    // Use defineProperty so we shadow any existing value without destroying it.
    const proxy = buildNostrProxy();
    try {
      Object.defineProperty(global, "nostr", {
        get() {
          return proxy;
        },
        set() {
          /* ignore attempts to overwrite */
        },
        configurable: true,
      });
    } catch (_) {
      global.nostr = proxy;
    }

    // Register message listener before the iframe loads
    global.addEventListener("message", onMessage);

    if (!config.forceIframe && nativeNostr) {
      const works = await probeNativeExtension(nativeNostr);
      if (works) {
        // The native extension is responsive — defer to it instead of the iframe.
        // Restore the native object and tear down our listener.
        try {
          Object.defineProperty(global, "nostr", {
            value: nativeNostr,
            writable: true,
            configurable: true,
          });
        } catch (_) {
          global.nostr = nativeNostr;
        }
        global.removeEventListener("message", onMessage);
        initialized = false;
        console.info(
          "nostr-bridge: responsive native extension found; iframe skipped.",
        );
        // Hand off to nostr-login if it is available on the page
        if (global.nostrLogin && typeof global.nostrLogin.init === "function") {
          global.nostrLogin.init({ bunkers: "", perms: "" });
        }
        return;
      }
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
  global.NostrBridge = { init };
})(window);
