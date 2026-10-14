# nostr-shard-signer

Gives any web page a standard NIP-07 `window.nostr` (`getPublicKey`, `signEvent`, `nip04`, `nip44`). Users sign in with their NIP-07 extension or a NIP-46 bunker, and, with a Web3Auth `clientId`, with Google/Apple/X. The key is held only in a cross-origin iframe.

This package is the loader and TypeScript types for [nostr-bridge.js](https://github.com/saintego/nostr-shard-signer). It doesn't bundle the bridge: `loadNostrBridge()` loads `nostr-bridge.js` from the signer it talks to, so the bridge and the signer always come from the same deployment.

> Alpha software with no security audit; not for high-value keys.

```bash
npm install nostr-shard-signer
```

```ts
import { loadNostrBridge } from "nostr-shard-signer";

// Client-side only (it rejects without `window`). Safe to call more than once.
const NostrBridge = await loadNostrBridge({
  clientId: "YOUR_WEB3AUTH_CLIENT_ID", // optional: adds Google/Apple/X sign-in
});

NostrBridge.onAuthChange(({ loggedIn, pubkey }) => {
  // pubkey is hex, or null when logged out
});

// Your own buttons (the floating widget has a Sign in button too):
// NostrBridge.login(); NostrBridge.logout();

// After sign-in, the standard NIP-07 API:
const signed = await window.nostr.signEvent({
  kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [], content: "hi",
});
```

React:

```tsx
useEffect(() => {
  let off = () => {};
  loadNostrBridge({ clientId: "YOUR_WEB3AUTH_CLIENT_ID" }).then((bridge) => {
    off = bridge.onAuthChange(setAuth);
  });
  return () => off();
}, []);
```

`loadNostrBridge(config)` takes the same options as `NostrBridge.init(config)`: `clientId`, `layout`, `buttonSize`, `mountSelector`, `forceIframe`, and `bunkerOrigin` / `registrarUrl` for a self-hosted signer.

## Types

The package types `NostrBridge` and exports its interfaces (`NostrBridgeConfig`, `NostrBridgeAuthState`, `NostrSignedEvent`, …). It leaves `window.nostr` alone so it coexists with other NIP-07 typings. If nothing else in your project declares `window.nostr`, add at the top of a file:

```ts
/// <reference types="nostr-shard-signer/window" />
```

## Setup

With a `clientId`, list `https://saintego.github.io` in your Web3Auth project's Allowlist URLs and register your site's origin in the [portal](https://saintego.github.io/nostr-shard-signer/portal/). Setup problems show up in the console with a fix hint.

Full reference: [llms-full.txt](https://saintego.github.io/nostr-shard-signer/llms-full.txt) · [README](https://github.com/saintego/nostr-shard-signer#readme)

## Versioning

0.x: minor versions may contain breaking changes. The hosted `nostr-bridge.js` reports its `NostrBridge.apiVersion`, and the loader warns in the console if it differs from the version these types describe.
