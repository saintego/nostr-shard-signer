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
 *       bunkerOrigin: "https://bunker.yourdomain.com",
 *       forceIframe:  false,
 *       layout:       "floating",      // "floating" | "in-place"
 *       buttonSize:   "standard",      // "standard" | "large_social_grid"
 *       mountSelector: "#nostr-btn",   // only used when layout === "in-place"
 *     });
 *   </script>
 *
 * Security notes:
 *  - All postMessage calls target the pinned bunkerOrigin exactly (no wildcard).
 *  - event.source is checked against the specific iframe contentWindow.
 *  - "null" origins are rejected unconditionally.
 *  - A 5-second probe timeout prevents locked extensions from hanging the queue.
 */

(function (global) {
  "use strict";

  // ── Build-time constant: replaced by your bundler / CI step ─────────────────
  // Set to your actual bunker origin, e.g. "https://bunker.yourdomain.com"
  var DEFAULT_BUNKER_ORIGIN = "https://bunker.yourdomain.com";

  var EXTENSION_TIMEOUT_MS = 5000; // How long to wait for a native extension
  var RPC_TIMEOUT_MS = 30000; // How long to wait for an iframe RPC reply
  var IFRAME_ID = "nostr-signer-iframe";
  var CONTAINER_ID = "nostr-signer-container";

  // ── State ────────────────────────────────────────────────────────────────────
  var config = {};
  var iframeEl = null;
  var containerEl = null;
  var authState = "unknown"; // "unknown" | "loggedIn" | "loggedOut"
  var currentPubkey = null;
  var pendingQueue = []; // items waiting for AUTH_STATE to arrive
  var pendingRequests = {}; // id -> { resolve, reject, timer }
  var reqCounter = 0;
  var resolvedOrigin = null; // pinned after first valid message from iframe
  var initialized = false;

  // ── CSS size map ─────────────────────────────────────────────────────────────
  var SIZES = {
    button: {
      standard: { width: "220px", height: "48px" },
      large_social_grid: { width: "320px", height: "136px" },
    },
    avatar: { width: "48px", height: "48px" },
    modal: { width: "420px", height: "580px" },
  };

  function getButtonDimensions() {
    var sz = config.buttonSize || "standard";
    return SIZES.button[sz] || SIZES.button.standard;
  }

  // ── DOM helpers ──────────────────────────────────────────────────────────────
  function injectStyles() {
    if (document.getElementById("nostr-bridge-styles")) return;
    var style = document.createElement("style");
    style.id = "nostr-bridge-styles";
    var isFloating = config.layout !== "in-place";
    style.textContent = [
      "#" + CONTAINER_ID + " {",
      "  position: " + (isFloating ? "fixed" : "relative") + ";",
      isFloating ? "  bottom: 24px; right: 24px;" : "",
      "  z-index: 2147483647;",
      "  transition: width 0.2s ease, height 0.2s ease;",
      "  overflow: hidden;",
      "  border: none;",
      "  background: transparent;",
      "}",
      "#" + IFRAME_ID + " {",
      "  width: 100%; height: 100%;",
      "  border: none; background: transparent; display: block;",
      "}",
    ].join("\n");
    document.head.appendChild(style);
  }

  function buildIframeSrc() {
    var origin = config.bunkerOrigin || DEFAULT_BUNKER_ORIGIN;
    // Use URL constructor for safe concatenation (no string injection)
    var url = new URL("/signer.html", origin);
    url.searchParams.set("clientId", config.clientId);
    url.searchParams.set("layout", config.layout || "floating");
    url.searchParams.set("buttonSize", config.buttonSize || "standard");
    url.searchParams.set("parentOrigin", global.location.origin);
    return url.toString();
  }

  function setContainerSize(state) {
    if (!containerEl) return;
    var dims;
    if (state === "button") {
      dims = getButtonDimensions();
    } else if (state === "avatar") {
      dims = SIZES.avatar;
    } else if (state === "modal") {
      dims = SIZES.modal;
    } else {
      return;
    }
    containerEl.style.width = dims.width;
    containerEl.style.height = dims.height;
  }

  function injectIframe() {
    if (document.getElementById(CONTAINER_ID)) return;

    injectStyles();

    containerEl = document.createElement("div");
    containerEl.id = CONTAINER_ID;
    var initDims = getButtonDimensions();
    containerEl.style.width = initDims.width;
    containerEl.style.height = initDims.height;

    iframeEl = document.createElement("iframe");
    iframeEl.id = IFRAME_ID;
    iframeEl.src = buildIframeSrc();

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

    containerEl.appendChild(iframeEl);

    if (config.layout === "in-place" && config.mountSelector) {
      var mount = document.querySelector(config.mountSelector);
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
    var cw = iframeWindow();
    if (!cw) throw new Error("nostr-bridge: iframe not available");
    var target = resolvedOrigin || config.bunkerOrigin || DEFAULT_BUNKER_ORIGIN;
    cw.postMessage(msg, target);
  }

  // ── Incoming message handler ─────────────────────────────────────────────────
  function onMessage(event) {
    // Reject null origins unconditionally (sandboxed contexts without allow-same-origin)
    if (!event.origin || event.origin === "null") return;

    var expected = config.bunkerOrigin || DEFAULT_BUNKER_ORIGIN;

    // Pin the origin on first contact; all future messages must match
    if (!resolvedOrigin) {
      if (event.origin !== expected) return;
      resolvedOrigin = event.origin;
    } else {
      if (event.origin !== resolvedOrigin) return;
    }

    // Source check: only messages from our specific iframe contentWindow
    if (event.source !== iframeWindow()) return;

    var data = event.data;
    if (!data || typeof data !== "object") return;

    // ── UI/State messages (custom schema) ────────────────────────────────────
    if (data.type === "AUTH_STATE") {
      authState = data.loggedIn ? "loggedIn" : "loggedOut";
      currentPubkey = data.pubkey || null;
      setContainerSize(data.loggedIn ? "avatar" : "button");
      flushQueue();
      return;
    }

    if (data.type === "AUTH_SUCCESS") {
      authState = "loggedIn";
      currentPubkey = data.pubkey;
      setContainerSize("avatar");
      flushQueue();
      return;
    }

    if (data.type === "RESIZE") {
      setContainerSize(data.state);
      return;
    }

    // ── NIP-46 RPC responses ─────────────────────────────────────────────────
    if (data.id !== undefined) {
      var pending = pendingRequests[data.id];
      if (!pending) return;
      clearTimeout(pending.timer);
      delete pendingRequests[data.id];
      if (data.error) {
        pending.reject(new Error(data.error));
      } else {
        pending.resolve(data.result);
      }
    }
  }

  // ── Queue management ─────────────────────────────────────────────────────────
  function flushQueue() {
    var queue = pendingQueue.splice(0);
    for (var i = 0; i < queue.length; i++) {
      var item = queue[i];
      if (authState === "loggedIn") {
        (function (it) {
          dispatchRpc(it.method, it.params).then(it.resolve).catch(it.reject);
        })(item);
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
        pendingQueue.push({
          method: method,
          params: params,
          resolve: resolve,
          reject: reject,
        });
        return;
      }
      if (authState === "loggedOut") {
        reject(new Error("nostr-bridge: user is not logged in"));
        return;
      }

      var id = "req_" + reqCounter++;
      var timer = setTimeout(function () {
        delete pendingRequests[id];
        reject(new Error("nostr-bridge: RPC timeout for '" + method + "'"));
      }, RPC_TIMEOUT_MS);

      pendingRequests[id] = { resolve: resolve, reject: reject, timer: timer };

      try {
        postToIframe({ id: id, method: method, params: params });
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
      getPublicKey: function () {
        if (authState === "loggedIn" && currentPubkey) {
          return Promise.resolve(currentPubkey);
        }
        return dispatchRpc("get_public_key", []).then(function (result) {
          currentPubkey = result;
          return result;
        });
      },

      signEvent: function (event) {
        return dispatchRpc("sign_event", [JSON.stringify(event)]).then(
          function (result) {
            return JSON.parse(result);
          },
        );
      },

      nip04: {
        encrypt: function (recipientHex, plaintext) {
          return dispatchRpc("nip04_encrypt", [recipientHex, plaintext]);
        },
        decrypt: function (senderHex, ciphertext) {
          return dispatchRpc("nip04_decrypt", [senderHex, ciphertext]);
        },
      },

      nip44: {
        encrypt: function (recipientHex, plaintext) {
          return dispatchRpc("nip44_encrypt", [recipientHex, plaintext]);
        },
        decrypt: function (senderHex, ciphertext) {
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
      var timer = setTimeout(function () {
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

    config = Object.assign(
      {
        layout: "floating",
        buttonSize: "standard",
        forceIframe: false,
        bunkerOrigin: DEFAULT_BUNKER_ORIGIN,
      },
      userConfig,
    );

    initialized = true;

    // Save a reference to any pre-existing window.nostr (native extension)
    var nativeNostr = typeof global.nostr !== "undefined" ? global.nostr : null;

    // Install our proxy synchronously so callers can queue immediately.
    // Use defineProperty so we shadow any existing value without destroying it.
    var proxy = buildNostrProxy();
    try {
      Object.defineProperty(global, "nostr", {
        get: function () {
          return proxy;
        },
        set: function (v) {
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
      var works = await probeNativeExtension(nativeNostr);
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
        return;
      }
    }

    // Inject iframe (deferred if DOM not ready yet)
    if (document.body) {
      injectIframe();
    } else {
      document.addEventListener("DOMContentLoaded", injectIframe);
    }
  }

  // ── Expose ───────────────────────────────────────────────────────────────────
  global.NostrBridge = { init: init };
})(window);
