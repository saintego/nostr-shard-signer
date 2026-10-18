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

`loadNostrBridge(config)` takes the same options as `NostrBridge.init(config)`: `clientId`, `layout`, `buttonSize`, `mountSelector`, `forceIframe`, `poweredBy`, and `bunkerOrigin` / `registrarUrl` for a self-hosted signer.

## Types

The package types `NostrBridge` and exports its interfaces (`NostrBridgeConfig`, `NostrBridgeAuthState`, `NostrSignedEvent`, …). It leaves `window.nostr` alone so it coexists with other NIP-07 typings. If nothing else in your project declares `window.nostr`, add at the top of a file:

```ts
/// <reference types="nostr-shard-signer/window" />
```

## Setup

### Nostr-only sign-in: nothing to set up

Call `loadNostrBridge()` without a `clientId`. Users sign in with a NIP-07 browser extension (Alby, nos2x…) or a NIP-46 bunker (nsec.app, Amber…). The console warns that Google/Apple/X sign-in is off; that's expected.

### Google/Apple/X sign-in: a Web3Auth project (once)

Social login goes through [Web3Auth](https://web3auth.io): the user signs in with Google, Apple or X, and Web3Auth's MPC network gives the signer iframe the user's key, which never leaves that iframe. You use your own Web3Auth project, and declare which sites may use it, so other sites can't use your project (and its quota).

1. **Create a project** in the [Web3Auth dashboard](https://dashboard.web3auth.io) (it now redirects to the MetaMask developer dashboard; free tier; network **Sapphire Mainnet**) and copy its **Client ID**. That is your `clientId`.

2. **Allowlist the origins** under Project Settings → Domains → Allowlist URLs:
   - `https://saintego.github.io`: the hosted signer iframe runs there, and it is what talks to Web3Auth. Without it, sign-in fails with `WEB3AUTH_INIT_FAILED`.
   - Your site's exact origin, e.g. `https://myapp.com` (scheme + host + port, no path). This authorizes your site to use the `clientId`. Without it, the signer refuses with `DOMAIN_NOT_REGISTERED`.
   - For local development, also your dev origin, e.g. `http://localhost:5173`.

3. **Register your origin in the [portal](https://saintego.github.io/nostr-shard-signer/portal/)** (recommended): connect a Nostr key, open **Register clientId**, and enter the `clientId` with your site's origin. This publishes a signed record to a registry on Nostr relays, which the signer checks as well, so sign-in keeps working when Web3Auth's allowlist can't be read. The portal only accepts origins that are already in the allowlist, and refuses localhost and http origins. Add more origins later with **Update Domains**. Without this step sign-in still works, and the console shows a `NOT_IN_REGISTRY` warning.

### When something is wrong

Setup problems are logged in the browser console with an error code and how to fix it. The [error table](https://saintego.github.io/nostr-shard-signer/llms-full.txt) (section 5) lists them all.

Full reference: [llms-full.txt](https://saintego.github.io/nostr-shard-signer/llms-full.txt) · [README](https://github.com/saintego/nostr-shard-signer#readme)

## Versioning

0.x: minor versions may contain breaking changes. The hosted `nostr-bridge.js` reports its `NostrBridge.apiVersion`, and the loader warns in the console if it differs from the version these types describe.
