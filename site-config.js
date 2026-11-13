/**
 * site-config.js: settings of the hosted site (portal, examples), in one place.
 * Deployed next to nostr-bridge.js by scripts/assemble-site.sh. Apps don't use
 * it: they pass their own clientId to NostrBridge.init().
 */
window.NOSTR_SHARD_SITE = Object.freeze({
  // The portal's Web3Auth client ID, registered for https://saintego.github.io
  // (and the PR preview origin) via the portal's Register tab.
  portalClientId:
    "BAOAjkerFp9u0leoDRvFeYVVt4h8v_xtHR863RaY2jg_epR3QDKmXR3sU18BW4mQTQvTDQh4FOPyNGj6wJLeH4Y",
  // The deployed registrar Worker.
  registrarUrl: "https://nostr-shard-registrar.nostr-shard-signer.workers.dev",
});
