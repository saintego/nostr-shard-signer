/**
 * nostr-shard-signer: loader for nostr-bridge.js.
 *
 * The bridge script is not bundled. loadNostrBridge() loads it from the signer
 * it talks to (<bunkerOrigin>/nostr-bridge.js), so the bridge and signer.html
 * always come from the same deployment and speak the same protocol.
 */

const DEFAULT_BUNKER_ORIGIN = "https://saintego.github.io/nostr-shard-signer";
// NostrBridge.apiVersion that this package's types describe.
export const API_VERSION = 1;

let loading = null; // in-flight or finished script load, shared by all calls

function bridgeScriptUrl(bunkerOrigin) {
  let url;
  try {
    url = new URL(bunkerOrigin);
  } catch (_) {
    throw new Error(
      "nostr-shard-signer: bunkerOrigin must be an absolute URL like " +
        DEFAULT_BUNKER_ORIGIN + " (got " + JSON.stringify(bunkerOrigin) + ")",
    );
  }
  return url.origin + url.pathname.replace(/\/$/, "") + "/nostr-bridge.js";
}

function loadScript(src) {
  return new Promise(function (resolve, reject) {
    const s = document.createElement("script");
    s.src = src;
    s.onload = function () {
      if (window.NostrBridge) resolve(window.NostrBridge);
      else reject(new Error("nostr-shard-signer: " + src + " loaded but did not define NostrBridge"));
    };
    s.onerror = function () {
      s.remove();
      reject(new Error("nostr-shard-signer: could not load " + src));
    };
    document.head.appendChild(s);
  });
}

/**
 * Loads nostr-bridge.js (once), calls NostrBridge.init(config) and resolves
 * with NostrBridge once window.nostr is installed. Safe to call more than once;
 * like init(), later calls keep the first config.
 */
export async function loadNostrBridge(config) {
  if (typeof window === "undefined" || typeof document === "undefined")
    throw new Error(
      "nostr-shard-signer: loadNostrBridge() runs in the browser only; call it from client-side code",
    );
  // Also reuses a bridge the page loaded with a <script> tag.
  if (window.NostrBridge) loading = loading || Promise.resolve(window.NostrBridge);
  if (!loading) {
    const src = bridgeScriptUrl((config && config.bunkerOrigin) || DEFAULT_BUNKER_ORIGIN);
    loading = loadScript(src).then(
      function (bridge) {
        // Bridges older than apiVersion speak version 1.
        const version = bridge.apiVersion === undefined ? 1 : bridge.apiVersion;
        if (version !== API_VERSION)
          console.warn(
            "nostr-shard-signer: " + src + " has NostrBridge API version " + version +
              ", this package's types describe version " + API_VERSION +
              ". Update the nostr-shard-signer package.",
          );
        return bridge;
      },
      function (err) {
        loading = null; // let a later call retry
        throw err;
      },
    );
  }
  const bridge = await loading;
  await bridge.init(config);
  return bridge;
}
