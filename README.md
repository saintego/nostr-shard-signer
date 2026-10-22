# nostr-shard-signer

**Sign in with Google, Apple or X for Nostr apps.** One `<script>` tag gives your web app a standard NIP-07 `window.nostr`: new users sign in with an account they already have and get a real Nostr keypair, and existing Nostr users sign in with their browser extension or NIP-46 bunker. No extension to install, no nsec to copy and paste. **[Live demo →](https://saintego.github.io/nostr-shard-signer)**

> [!WARNING]  
> **ALPHA RELEASE — USE AT YOUR OWN RISK**  
> `nostr-shard-signer` is currently in **Alpha** and has **not** undergone a formal security audit.
>
> Because this library manages private key reconstruction in a browser/iframe context, it is vulnerable to frontend supply chain attacks (e.g., if the CDN or iframe host is compromised, keys could be exposed). **Do not use this to secure high-value wallets or significant funds.**
>
> Security reviews, testing, and pull requests are highly encouraged!

## Login example

```html
<script src="https://saintego.github.io/nostr-shard-signer/nostr-bridge.js"></script>
<script type="module">
  // Fires once the state is known (restored session) and on every sign-in / sign-out.
  NostrBridge.onAuthChange(({ loggedIn, pubkey }) => {
    console.log(loggedIn ? "Signed in as " + pubkey : "Signed out");
  });

  // Shows the "Sign in" button; after login, use window.nostr like any NIP-07 extension.
  // Without clientId, users sign in with a Nostr extension or NIP-46 bunker only.
  await NostrBridge.init({ clientId: "YOUR_WEB3AUTH_CLIENT_ID" });
</script>
```

For Google/Apple/X sign-in, your domain must be registered for the `clientId` first, see [Getting Started](#getting-started-2-minutes). A complete page that also publishes a note is in [`examples/minimal.html`](examples/minimal.html).

> **Using an AI coding agent?** Point it at [`llms.txt`](https://saintego.github.io/nostr-shard-signer/llms.txt) (short) or [`llms-full.txt`](https://saintego.github.io/nostr-shard-signer/llms-full.txt) (complete reference). Types: [`nostr-bridge.d.ts`](nostr-bridge.d.ts). Working page: [`examples/minimal.html`](examples/minimal.html).

## OAuth login on Nostr

Nostr has no accounts or passwords: a user *is* a keypair, and every post is signed with the private key (nsec). That is why most Nostr apps start by asking people to install a signer extension or paste an nsec, and why most people leave at that step.

nostr-shard-signer lets them sign in the way they do everywhere else, with Google, Apple or X, and still ends with a normal Nostr key:

1. The user clicks **Sign in** and picks Google, Apple or X in the [Web3Auth](https://web3auth.io) sheet.
2. Web3Auth checks the OAuth login and its MPC network returns the user's secp256k1 private key. The key is split into shares held by independent nodes; no single party, Web3Auth included, holds the whole key.
3. The key is put back together only inside the signer iframe, which runs on a different origin than your app. It becomes the user's Nostr keypair (npub / nsec).
4. Your app talks to it through `window.nostr`, exactly as it would to a browser extension. The page gets the pubkey and signed events, never the nsec.

The next time the user signs in with the same account, they get the same key back. Nothing is stored on your server, and there's no seed phrase to lose.

What users get:

- A standard Nostr identity. Their npub works across Nostr; profiles, follows and notes made in your app show up in every other client.
- A backup prompt. After a few posts, the widget asks them to back up their key: a password-encrypted backup (NIP-49 `ncryptsec`) to copy or download, or the plain nsec. A backup made on one site counts on every site.
- A way out. The widget's profile menu has an **Export key** button that shows their nsec, so they can move it to an extension or bunker and keep using the same identity without your app.
- A profile from day one. If they have no Nostr profile yet, the widget shows the name and picture from their Google, Apple or X account.

Know before you ship:

- **The key belongs to your Web3Auth project.** Web3Auth gives each project (`clientId`) its own keys, so the same Google account gets a different npub in an app with another `clientId`. Never change the `clientId` of a live app: every OAuth user would get a new, empty identity.
- **Each provider is a separate identity.** Signing in with Apple doesn't give the npub the user got with Google.
- **The project owner is trusted with users' keys.** Whoever owns the Web3Auth project (`clientId`) decides which sites may use it, so they can run Web3Auth on a page of their own and get the key of any user who signs in there. The signer keeps the key away from your page's *code*, not from the *owner* of the `clientId`. Users trust an app's owner with the identity they create in that app, as with any Web3Auth embedded wallet.
- Users who already have a Nostr key shouldn't use OAuth. They sign in with their extension or bunker from the same **Sign in** sheet and keep their identity.

## Why nostr-shard-signer

- **Onboarding without Nostr knowledge.** New users start with a Google, Apple or X login, not a key-management lesson.
- **Drop-in NIP-07.** Code written for Alby or nos2x works unchanged; there is no new signing API to learn.
- **Every user in one button.** OAuth for newcomers, NIP-07 extensions and NIP-46 bunkers for existing users, all behind the same `window.nostr`.
- **The key stays out of your page's code.** It lives only in a cross-origin iframe, so your app's code, its dependencies and an XSS bug can't read it. (The owner of the Web3Auth project still can obtain it; see [Security Model](#security-model).)
- **No backend to run.** Use the hosted signer and registrar; you only need a free Web3Auth `clientId`. Nostr-only sign-in needs nothing at all.
- **Your quota stays yours.** A domain may only use your `clientId` once it is in your Web3Auth allowlist or registered by you on Nostr.
- **Sessions survive reloads**, and confirmations for sensitive actions (profile changes, DMs, zaps) are built in.
- **Open source** (MIT) and self-hostable.

## Compared with other approaches

|                                             | nostr-shard-signer             | [nostr-login](https://github.com/nostrband/nostr-login) | [nsec.app](https://nsec.app) ([Noauth](https://github.com/nostrband/noauth)) | [window.nostr.js](https://github.com/fiatjaf/window.nostr.js) | [Pomegranate](https://pkg.go.dev/fiatjaf.com/pomegranate) | OAuth bunker (key on a server) | Web3Auth SDK in your app | Key generated in the page |
| ------------------------------------------- | :----------------------------: | :-----------------------------: | :-------------------------: | :-------------------: | :-----------------------------: | :-------------------------: | :----------------------: | :-----------------------: |
| What it is                                  | `window.nostr` provider        | `window.nostr` provider         | Web-based NIP-46 bunker     | `window.nostr` provider | Sharded NIP-46 bunker         | Server-side NIP-46 bunker   | Wallet SDK               | DIY                       |
| Sign in with Google / Apple / X             | ✅                             | ❌                              | ❌                          | ❌                    | ✅ Google                       | ✅                          | ✅                       | ❌                        |
| New users without a Nostr key               | ✅ OAuth                       | ✅ sign-up at a bunker, or a local key | ✅ create a key there | ✅ sign-up at a bunker | ✅                             | ✅                          | ✅                       | ✅                        |
| Existing users: extension or bunker         | ✅ same button                 | ✅ (+ read-only)                | ✅ import key               | ✅                    | ✅ import key                   | usually ❌                  | ❌ you build it          | ❌ nsec paste             |
| Where the key is while in use               | signer iframe, user's browser  | extension, bunker, or the page (local keys) | nsec.app, user's browser | the user's bunker | never whole: shards on operators | the bunker server         | your page                | your page                 |
| Your page's JS (and XSS) can't read the key | ✅                             | ✅ (❌ with local keys)         | ✅                          | ✅                    | ✅                              | ✅ (the server can)         | ❌                       | ❌                        |
| The app's owner can't obtain the key        | ❌ with OAuth (✅ extension / bunker) | ✅ (❌ with local keys)   | ✅                          | ✅                    | ✅                              | ✅ (the bunker operator can) | ❌                      | ❌                        |
| No server ever holds the whole key          | ✅                             | ✅ (depends on the bunker)      | ✅                          | ✅ (depends on the bunker) | ✅                         | ❌                          | ✅                       | ✅                        |
| Account recovery                            | OAuth login                    | depends on the signer           | password-encrypted backup   | depends on the signer | Google login + operators        | OAuth login                 | OAuth login              | ❌                        |
| Servers involved                            | hosted signer page + Web3Auth  | none                            | nsec.app                    | none                  | central service + operators     | the bunker server           | Web3Auth                 | none                      |
| Standard `window.nostr`, no app changes     | ✅                             | ✅                              | needs a NIP-46 client       | ✅                    | needs a NIP-46 client           | needs a NIP-46 client       | ❌ you write the glue    | ❌                        |

**What sets nostr-shard-signer apart:** it combines sign-in with Google, Apple or X, a drop-in `window.nostr` that also serves extension and bunker users from the same button, and a key that neither your page nor any server can read. nostr-login, nsec.app and window.nostr.js onboard new users into a Nostr signer instead of an account they already have. An OAuth bunker is simple, but its server holds every user's key. Pomegranate goes further on custody (the key is never whole, signatures are combined from shards), at the cost of a central service and a NIP-46 client in your app.

**The trade-offs:** OAuth users depend on Web3Auth to get their key back, the owner of the app's Web3Auth project can obtain their key, and the key is put together in the browser while they are signed in, so this suits everyday social apps rather than high-value keys. Users can export their nsec at any time to remove that dependency.

## FAQ

**How do I make my Nostr web page easy to log in to for people with no Nostr experience?**
Use nostr-shard-signer. Users sign in with the Google, Apple or X button they know, and get a Nostr account, created and kept safe for them, without installing anything or seeing a key. People who already use Nostr sign in with their extension or bunker from the same button.

**Is this a custodial login?**
Not in the usual sense: no server stores the user's key. Web3Auth's MPC network splits it into shares, and it is put back together only in the user's browser, inside the signer iframe. But the owner of the app's Web3Auth project (`clientId`) can obtain it: they decide which sites may use the project, so they can run Web3Auth on a page of their own and get the key of any user who signs in there. Users therefore trust the app's owner with the identity they create in that app. Users who don't want that sign in with their own extension or bunker, or export their key and switch to one.

**Do users get a "real" Nostr account?**
Yes. It is an ordinary secp256k1 keypair. Their npub, profile, follows and notes work in every Nostr client.

**Will a user have the same npub in another app that uses this library?**
Only if that app uses the same Web3Auth `clientId`. Web3Auth scopes keys to the project, so different apps give the same Google account different npubs. To use one identity everywhere, a user exports their nsec into an extension or bunker and signs in with that.

**Can several of my sites share one identity per user?**
Yes. Register all of them for the same `clientId`: a user who signs in with the same account gets the same npub on each.

**Does the same email give the same key with Google and with Apple?**
No. Each login provider is a separate Web3Auth connection with its own key, even for the same email address. Web3Auth's group connections can link providers to one key, but the signer doesn't configure them, and they use other keys than the single connections, so turning them on later would also change existing users' npubs.

**Can I change my `clientId` later?**
Not for a live app. Your OAuth users' keys are tied to it; a new `clientId` gives them new, empty identities. Pick the project once, on Sapphire Mainnet.

**Can a user move their account away from Google?**
Yes. The widget's profile menu has an **Export key** button that shows their nsec. They import it into an extension (Alby, nos2x…) or a bunker (Amber, nsecBunker…) and keep the same identity, with or without your app.

**What if Web3Auth goes away or my project is closed?**
OAuth users could no longer get their key back through Google, Apple or X. Users who exported their nsec are unaffected. That is one reason this library suits everyday social apps rather than high-value keys.

**Does it work for users who already use Nostr?**
Yes. The same **Sign in** sheet offers their NIP-07 extension or a NIP-46 bunker, and their existing identity is used. No `clientId` is needed for that; call `NostrBridge.init()` without one for Nostr-only sign-in.

**Do I have to change my Nostr code?**
No. Anything written against `window.nostr` (`getPublicKey`, `signEvent`, `nip04`, `nip44`) keeps working. The bridge signs and encrypts; publishing to relays stays your app's job.

**Does it need a backend or cost anything?**
The hosted signer and registrar are free to use, and there is no server of your own to run. Google/Apple/X sign-in needs a Web3Auth project; check Web3Auth's pricing for its free-tier limits. You can also self-host everything (see [Deployment](#deployment)).

**Can my page or an XSS bug read the user's key?**
No. The key only exists in the signer iframe on another origin, which the browser keeps apart from your page. Your page only receives the pubkey and signed events. The risks are the signer host itself (see the warning at the top) and the owner of the Web3Auth project, who can obtain users' keys (see "Is this a custodial login?").

**Which signing requests need confirmation?**
With OAuth login, ordinary public content is signed without asking: notes, reactions, comments, wiki articles, bookmarks, calendar events, app data (kind 30078) and media uploads to nostr.build. Users can turn each of these off per site in Settings. Profile, follow list and relay list changes, deletions, other kinds such as zaps, `nip04.encrypt` and every decrypt show a confirmation in the widget. Extensions and bunkers apply their own rules.

**Does it work with React, Vue, Svelte or Next.js?**
Yes. Use the [`nostr-shard-signer`](https://www.npmjs.com/package/nostr-shard-signer) npm package's `loadNostrBridge()` client-side, or the script tag in your HTML shell. [`llms-full.txt`](llms-full.txt) has framework notes.

## How it works

**Two login paths, one API:**

| Mode                                      | Who it's for                                  | How it works                                                                                                                                                                                                                |
| ----------------------------------------- | --------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Web3Auth OAuth**                        | Users new to Nostr or who prefer social login | Google, Apple, or X → MPC key is derived and held inside a sandboxed cross-origin iframe. The nsec never leaves that context.                                                                                               |
| **NIP-07 extension or NIP-46 bunker**     | Users who already hold their own Nostr key    | An installed extension (Alby, nos2x…) is used directly. Without one, [`window.nostr.js`](https://github.com/fiatjaf/window.nostr.js/) connects to a NIP-46 bunker (Amber, nsecBunker…) over an encrypted relay channel. The parent app sees only signed events — never the key. |

The bridge detects a stored session on load and switches modes transparently. Both expose an identical `window.nostr` API, so client code is the same regardless of which path the user chose.

> **Need zero client-side key reconstruction?** Users can keep their key in a NIP-46 bunker they control, such as Amber on their phone or a self-hosted [nsecBunker](https://nsecbunker.com); nostr-shard-signer then just passes calls through.

## Security Model

| Threat                                  | Mitigation                                                                                                        |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Parent page JS reading your nsec        | Key lives only in a cross-origin iframe; Same-Origin Policy makes it unreachable                                  |
| Owner of the clientId obtaining users' keys | **Not prevented.** The owner controls the Web3Auth project's allowlist, so they can run Web3Auth on a page of their own and get the key of any user who signs in there (true of every Web3Auth embedded wallet). Users trust the app owner with the identity they create in that app; users who don't sign in with their own extension or bunker |
| Browser extension / XSS on parent page  | Same isolation — the iframe context is physically separate                                                        |
| Domain spoofing to steal Web3Auth quota | The page origin must be in the NIP-33 registry on Nostr or in the clientId's Web3Auth allowlist (only its owner can edit it); the registrar only registers allowlisted origins |
| Rogue iframe injected by attacker       | `event.source === window.parent` check + `_parentOrigin` derived from `document.ancestorOrigins` (not URL params) |
| null-origin postMessage attacks         | All `window.addEventListener("message")` handlers reject `event.origin === "null"` unconditionally                |

---

## Getting Started (2 minutes)

### 1. Set up Google/Apple/X sign-in (one-time, optional)

Skip this step for Nostr-only sign-in (extension or NIP-46 bunker) and call `NostrBridge.init()` without a `clientId`.

1. Get a Web3Auth `clientId` (free, Sapphire Mainnet) from [Web3Auth](https://web3auth.io)
2. In its dashboard, under Project Settings → Domains → Allowlist URLs, add `https://saintego.github.io` and your app's origin (e.g. `https://myapp.com`).
3. In the [Developer Portal](https://saintego.github.io/nostr-shard-signer/portal/), connect your Nostr key, open the **Register clientId** tab, and register the `clientId` with your app's origin. The registrar only accepts origins that are in the Web3Auth allowlist.

The signer accepts an origin found in either the registry or the Web3Auth allowlist, and warns in the console when one of them is missing it.

### 2. Add one script tag to your app

```html
<script src="https://saintego.github.io/nostr-shard-signer/nostr-bridge.js"></script>
```

### 3. Call standard `window.nostr` — just like any NIP-07 extension

```js
// Initialize the bridge (required once). clientId is optional; bunkerOrigin and
// registrarUrl default to the hosted signer; set them only when self-hosting.
await NostrBridge.init({ clientId: "YOUR_WEB3AUTH_CLIENT_ID" });

// After the user signs in via the widget, use the standard NIP-07 API
const pubkey = await window.nostr.getPublicKey();
console.log("User pubkey:", pubkey);

// Sign an event
const event = {
  kind: 1,
  created_at: Math.floor(Date.now() / 1000),
  tags: [],
  content: "Hello Nostr!",
};
const signed = await window.nostr.signEvent(event);

// Encrypt/decrypt (if needed)
const encrypted = await window.nostr.nip04?.encrypt("target-pubkey", "secret");
const decrypted = await window.nostr.nip04?.decrypt("sender-pubkey", encrypted);
```

**That's it.** Your app now has:

- ✅ Web3Auth OAuth for new users (Google, Apple, X)
- ✅ NIP-07 extensions (Alby, nos2x…) and NIP-46 bunkers (Amber, nsecBunker…) for existing Nostr users
- ✅ Automatic session persistence across page reloads
- ✅ Zero friction — users pick their preferred login path

### Why no big rewrite is needed

The bridge **only** uses the standard NIP-07 API:

- `window.nostr.getPublicKey()`
- `window.nostr.signEvent(event)`
- `window.nostr.nip04.encrypt/decrypt()`
- `window.nostr.nip44.encrypt/decrypt()`

If your app already uses any Nostr extension (Alby, nos2x, etc.), replacing it with this bridge is a **drop-in substitute** — your code stays the same.

### Optional: React to login/logout, use your own buttons

```js
// Called with the current state once known, then on every change. Returns unsubscribe.
const unsubscribe = NostrBridge.onAuthChange(({ loggedIn, pubkey }) => {
  if (loggedIn) console.log("User logged in:", pubkey);
  else console.log("User logged out");
});

// Plain-HTML alternative: the same data as a window event.
window.addEventListener("nostr-bridge:auth", (e) => console.log(e.detail.loggedIn));

// Your own buttons (the floating widget keeps working alongside them).
loginButton.onclick = () => NostrBridge.login(); // opens the sign-in modal
logoutButton.onclick = () => NostrBridge.logout();
```

`NostrBridge.init()` is idempotent (a second call returns the first call's promise, so React StrictMode needs no guard), and `NostrBridge.ready` resolves once it has completed. The older `message` event with `e.data.type === "AUTH_STATE"` and `e.origin === ""` is still dispatched.

The script tag can also carry the config, so no init call is needed:

```html
<script src="https://saintego.github.io/nostr-shard-signer/nostr-bridge.js"
        data-client-id="YOUR_WEB3AUTH_CLIENT_ID" data-layout="floating"></script>
```

#### npm (bundled apps)

The [`nostr-shard-signer`](https://www.npmjs.com/package/nostr-shard-signer) package replaces the script tag in apps built with a bundler, and ships the TypeScript types:

```bash
npm install nostr-shard-signer
```

```ts
import { loadNostrBridge } from "nostr-shard-signer";

// Client-side only. Instead of NostrBridge.init(config); also idempotent.
const NostrBridge = await loadNostrBridge({ clientId: "YOUR_WEB3AUTH_CLIENT_ID" });
NostrBridge.onAuthChange(({ loggedIn, pubkey }) => { /* ... */ });
```

The package doesn't bundle the bridge: `loadNostrBridge()` loads `nostr-bridge.js` from the signer it talks to (`<bunkerOrigin>/nostr-bridge.js`), so the bridge and `signer.html` always come from the same deployment. To type `window.nostr` as well, add `/// <reference types="nostr-shard-signer/window" />`.

Without npm, [`nostr-bridge.d.ts`](nostr-bridge.d.ts) types `NostrBridge` and exports its interfaces (`import type { NostrBridgeConfig, NostrBridgeAuthState } from "./nostr-bridge"`). It leaves `window.nostr` alone so it coexists with other NIP-07 typings; include [`nostr-bridge-window.d.ts`](nostr-bridge-window.d.ts) as well if nothing else declares `window.nostr`.

> **Most apps don't need this.** If `window.nostr.getPublicKey()` succeeds, the user is logged in. If it throws, they're not — simple as that.

### Setup errors

If the signer can't start (domain not registered for the clientId, Web3Auth allowlist missing, …) the bridge logs `nostr-bridge: signer error CODE: …` with a fix hint in the page console, and dispatches `{ type: "SIGNER_ERROR", code, message, hint }` as a `message` event with `e.origin === ""`. If the page has an extension or window.nostr.js, the widget's Sign in button still works through it. The codes are listed in [`llms-full.txt`](llms-full.txt).

---

## Architecture

```
┌─────────────────────────────────────────────┐
│  Parent App  (app.example.com)              │
│                                             │
│  <script src="nostr-bridge.js">             │
│  window.nostr  ← Proxy object               │
│                                             │
│  ┌───────────────────────────────────────┐  │
│  │ <iframe src="<pages>/signer.html">    │  │
│  │                                       │  │
│  │  signer.html                          │  │
│  │  ├─ Web3Auth MPC login UI             │  │
│  │  ├─ nsec held in isolated JS context  │  │
│  │  └─ Signs/encrypts via nostr-tools    │  │
│  └───────────────────────────────────────┘  │
│          ↑↓  postMessage (NIP-46 RPC)       │
└─────────────────────────────────────────────┘
                        ↑
             NIP-33 registry check
                        ↑
┌─────────────────────────────────────────────┐
│  registrar-worker.js  (Cloudflare Worker)   │
│  POST /register  POST /update (two-phase)   │
│  REGISTRY_KV: short-lived mutex (60s TTL)   │
│  CHALLENGES_KV: nonces (TTL 5m)             │
│  Source of truth: NIP-33 events on relays   │
└─────────────────────────────────────────────┘
                        ↑
         register/update via UI or curl
                        ↑
┌─────────────────────────────────────────────┐
│  portal/index.html  (GitHub Pages)          │
│  ├─ nostr-bridge.js → window.nostr          │
│  ├─ Connect Nostr key (Alby / NIP-07)       │
│  ├─ Register tab: clientId + domain         │
│  └─ Update tab: sign nonce (kind 27235)     │
└─────────────────────────────────────────────┘
```

### Three-state iframe UI

```
[Login Button] ──login──► [Floating Avatar] ──click──► [Profile Modal]
                                 ▲                            │
                                 └──────────── close ─────────┘
```

The iframe resizes its container by sending `{ type: "RESIZE", state: "button" | "avatar" | "modal" }` messages to the parent.

---

## Login Modes

### Mode 1 — Web3Auth OAuth (default)

Users click the login button inside the iframe, pick a social provider (Google, Apple, X), and Web3Auth derives a Nostr keypair via MPC. The nsec is reconstructed only inside the cross-origin iframe context and is never serialised to `localStorage` or sent over the wire.

Unlike storing an nsec on a server, MPC splits the key into threshold shares distributed across independent nodes — no single party, including Web3Auth itself, ever holds the complete key, so a server breach yields only an unusable fragment. The key is still put back together for whoever runs Web3Auth with the project's `clientId` on an allowlisted page, which the project owner controls (see [Security Model](#security-model)).

This is the recommended mode for apps whose users may not have a Nostr identity yet.

### Mode 2 — NIP-46 Bunker via `window.nostr.js`

For users who already control their Nostr key, the bridge optionally loads [`window.nostr.js`](https://github.com/fiatjaf/window.nostr.js) (WNJ) — a lightweight NIP-46 client that connects to any remote bunker over Nostr relays.

**How the handoff works:**

1. `NostrBridge.init()` loads the WNJ CDN bundle (if `forceIframe: false`).
2. Clicking **Sign in** opens the Web3Auth login with a *Nostr signer or bunker* option right above it. Picking that opens WNJ's connect UI (bunker URL entry or QR scan for Amber).
3. Once the user connects, WNJ stores the bunker session in `localStorage` and exposes `window.nostr`.
4. The bridge detects WNJ's session and switches to `MODE_WNJ`: all `window.nostr` calls are routed to WNJ; the Web3Auth iframe is hidden.
5. On subsequent page loads the session is restored silently — no UI shown, no modal opened.

**Compatible remote signers:**

| Signer                                        | Platform    | Notes                              |
| --------------------------------------------- | ----------- | ---------------------------------- |
| [Amber](https://github.com/greenart7c3/Amber) | Android     | Phone acts as bunker via NIP-46    |
| [nsecBunker](https://nsecbunker.com)          | Self-hosted | Full custody, relay of your choice |

Any other NIP-46 remote signer works too: paste its `bunker://` URL, or scan the `nostrconnect://` QR code with the signer app.

**`NostrBridge.init()` option:**

```js
NostrBridge.init({
  clientId: "YOUR_WEB3AUTH_CLIENT_ID",
  forceIframe: false, // default — loads WNJ; set true to skip WNJ entirely
});
```

Setting `forceIframe: true` disables WNJ loading and always uses the Web3Auth iframe, regardless of any stored bunker session.

---

---

## File Structure

```
nostr-shard-signer/
├── nostr-bridge.js          # Parent wrapper — injects iframe, proxies window.nostr
├── nostr-bridge.d.ts        # TypeScript declarations for NostrBridge
├── nostr-bridge-window.d.ts # Opt-in: types window.nostr as the bridge's signer
├── llms.txt, llms-full.txt  # Docs for AI coding agents (published to GitHub Pages)
├── npm/                     # npm package "nostr-shard-signer": loadNostrBridge() + types
├── tests/                   # Playwright smoke tests (bridge + signer + loader), type tests
├── examples/minimal.html    # Minimal integration example
├── bunker/                  # Vite + React + TypeScript bunker app
│   ├── src/                 # App source (compiles → signer.html on GitHub Pages)
│   └── vite.config.ts
├── portal/
│   └── index.html           # Developer portal — register/update clientIds via UI
├── registrar/
│   ├── registrar-worker.js  # Cloudflare Worker — NIP-33 registry API
│   ├── wrangler.toml        # Worker configuration
│   └── package.json
└── .github/
    └── workflows/
        └── deploy.yml       # CI/CD — Pages + Cloudflare Worker on push to main
```

On every push to `main`, GitHub Actions publishes three assets to GitHub Pages and deploys the Cloudflare Worker:

| URL                                                           | Asset                         |
| ------------------------------------------------------------- | ----------------------------- |
| `https://<user>.github.io/nostr-shard-signer/nostr-bridge.js` | CDN bundle                    |
| `https://<user>.github.io/nostr-shard-signer/signer.html`     | iframe bunker                 |
| `https://<user>.github.io/nostr-shard-signer/portal/`         | Developer registration portal |

---

## Testing

```bash
npx playwright install chromium   # once
npm test                          # builds the signer, type-checks the npm package, runs Playwright
npm run test:e2e                  # Playwright only, against the existing bunker/dist build
```

The Playwright smoke tests (`tests/`) serve the built signer and `nostr-bridge.js` on fake origins with no real network, and sign in through a fake NIP-07 extension, so they need no clientId. They cover the bridge ↔ signer round trip, login/logout, session restore, the protocol handshake and the npm loader. Web3Auth sign-in is not covered. CI runs them on every PR (`.github/workflows/test.yml`).

## Publishing the npm package

The `npm/` workspace is the [`nostr-shard-signer`](https://www.npmjs.com/package/nostr-shard-signer) package: `loadNostrBridge()` plus the types. Its `prepack` copies `nostr-bridge.d.ts`, `nostr-bridge-window.d.ts` and `LICENSE` from the repo root, which stay the source of truth. There is no build step.

A release is only needed when the types or the loader change. Changes to `nostr-bridge.js` or the signer go live through the Pages deploy; npm users get them without a new package version.

### Releasing a version

1. **Bump the version** on a branch, together with the change or after it:

   ```bash
   npm version patch --workspace=npm   # 0.1.0 → 0.1.1: fixes, additions
   npm version minor --workspace=npm   # 0.1.0 → 0.2.0: breaking changes (while 0.x)
   ```

   This edits `npm/package.json` and `package-lock.json` only (no git tag). Commit, open a PR, merge. Use npm 11 (`npm install -g npm@11`, or Node 24): npm 10 rewrites the lockfile, dropping its `libc` entries.

2. **Create a GitHub release** from `main`: Releases → Draft a new release → new tag `npm-v<version>` (e.g. `npm-v0.1.1`), target `main`, title `nostr-shard-signer <version>`, notes on what changed for package users → Publish release.

3. The **Stage npm package** workflow (`.github/workflows/npm-publish.yml`) checks that the tag matches `npm/package.json` and isn't published yet, runs `npm test`, and **stages** the version with provenance: it is uploaded to npm but not public yet. Check the run in the Actions tab; its summary repeats the next step.

4. **Approve it** with your 2FA code. This needs npm 11.19 or newer (`npm install -g npm@11`), logged in with `npm login`:

   ```bash
   npm stage list nostr-shard-signer        # shows the staged version and its <stage-id>
   npm stage download <stage-id>            # optional: inspect the exact tarball
   npm stage approve <stage-id>             # publishes it; asks for 2FA
   ```

   A wrong build can be dropped with `npm stage reject <stage-id>` instead. Then check the version on [npmjs.com](https://www.npmjs.com/package/nostr-shard-signer).

Why staged: CI never holds the right to publish. Even if this repository or the workflow were compromised, nothing reaches npm without a maintainer's 2FA, which matters for a package whose code runs in other people's sites.

Prereleases: a version like `0.2.0-beta.1` (`npm version prerelease --preid beta --workspace=npm`) is staged under the `next` dist-tag, so `npm install nostr-shard-signer` keeps installing the last stable version; testers use `nostr-shard-signer@next`.

A published version can't be changed, and its number can't be reused even after unpublishing (only allowed within 72 hours). Fix mistakes with a new patch version, and mark a bad one with `npm deprecate nostr-shard-signer@<version> "<reason>"`.

### One-time setup (done once per repository)

- **npm:** npmjs.com → nostr-shard-signer → Settings → Trusted publishing → GitHub Actions: user `saintego`, repository `nostr-shard-signer`, workflow `npm-publish.yml`, environment `npm`, permission **stage publish only** (leave publish off; a direct `npm publish` from the workflow then fails with "403 OIDC permission denied for this action"). Under Publishing access, choose "Require two-factor authentication and disallow tokens".
- **GitHub:** Settings → Environments → New environment `npm` (the trusted publisher only accepts runs in it). No required reviewers needed: the 2FA approval on npm is the gate.

### Manual fallback

From an up-to-date `main`, logged in with `npm login` (publishing asks for your 2FA code):

```bash
npm test
npm publish --workspace=npm --dry-run   # what would be uploaded
npm publish --workspace=npm
```

---

## Deployment

### 1. One-time setup

#### a. Generate the root keypair

The root keypair signs all NIP-33 registry events. Keep the private key secret; only the public key is embedded in `signer.html`.

```bash
node -e "
const {generateSecretKey, getPublicKey} = require('nostr-tools');
const sk = generateSecretKey();
const pk = getPublicKey(sk);
const skHex = Buffer.from(sk).toString('hex');
console.log('ROOT_PRIVATE_KEY_HEX =', skHex);
console.log('ROOT_PUBKEY_HEX      =', pk);
"
```

#### b. Configure the bunker

In `bunker/src/App.tsx` (or the compiled output), replace the placeholder:

```ts
const ROOT_PUBKEY_HEX = "__ROOT_PUBKEY_HEX__";
// → your actual hex public key, e.g.:
const ROOT_PUBKEY_HEX = "a3b2...";
```

Optionally adjust:

- `REGISTRY_RELAYS` — array of relays that host your NIP-33 events
- `PUBLISH_RELAYS` — relays to broadcast profile updates to

The bunker is a Vite + React + TypeScript app. Build it with:

```bash
cd bunker && npm install && npm run build
```

The compiled output is published to GitHub Pages as `signer.html` by the deploy workflow.

#### c. Create the Cloudflare KV namespaces (once)

```bash
cd registrar
npm install

wrangler kv:namespace create "REGISTRY_KV"
# → Copy the returned id into wrangler.toml  binding = "REGISTRY_KV"
wrangler kv:namespace create "CHALLENGES_KV"
# → Copy the returned id into wrangler.toml  binding = "CHALLENGES_KV"

# Store the private key as a Cloudflare secret — never commit it
wrangler secret put ROOT_PRIVATE_KEY_HEX
# → Paste ROOT_PRIVATE_KEY_HEX when prompted
```

#### d. Add GitHub repository secrets

In **Settings → Secrets → Actions**, add:

| Secret                  | Value                                               |
| ----------------------- | --------------------------------------------------- |
| `CLOUDFLARE_API_TOKEN`  | Cloudflare API token with `Workers:Edit` permission |
| `CLOUDFLARE_ACCOUNT_ID` | Your Cloudflare account ID                          |

#### e. Enable GitHub Pages

In **Settings → Pages**, set source to **GitHub Actions**.

#### f. Update the portal registrar URL

In `portal/index.html`, replace the placeholder:

```js
const REGISTRAR_URL = "https://nostr-shard-registrar.__ACCOUNT__.workers.dev";
```

### 2. Automated deploy (push to `main`)

After the one-time setup, every push to `main` automatically:

1. Publishes `nostr-bridge.js`, `signer.html`, and `portal/index.html` to GitHub Pages
2. Deploys `registrar-worker.js` to Cloudflare Workers

```
https://<user>.github.io/nostr-shard-signer/nostr-bridge.js   ← CDN bundle
https://<user>.github.io/nostr-shard-signer/signer.html        ← iframe bunker
https://<user>.github.io/nostr-shard-signer/portal/            ← developer portal
```

### PR previews

Pull requests from this repo are built and deployed to Cloudflare Pages (`.github/workflows/preview.yml`) at one shared https URL, which the workflow posts as a PR comment. The registry refuses localhost, so use this URL to test signer changes. One-time setup:

- Give `CLOUDFLARE_API_TOKEN` the **Cloudflare Pages: Edit** permission as well.
- Add the preview origin to every clientId you test with, including the portal's own: use the portal's **Register** tab with the same clientId, signed in with the key that owns it. That adds the domain. Don't use **Update Domains**, which replaces the whole list. Also add the origin to the Web3Auth Allowlist URLs.

All PRs share the URL, so the most recent push wins. The preview uses the production registrar Worker.

### 3. Register your first clientId

**Option A — Portal UI** (recommended)

Open `https://<user>.github.io/nostr-shard-signer/portal/`, connect your Nostr key (Alby or any NIP-07 extension), fill in your `clientId` and domain, and click **Register**.

**Option B — curl**

```bash
curl -X POST https://nostr-shard-registrar.<account>.workers.dev/register \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "YOUR_WEB3AUTH_CLIENT_ID",
    "npub":     "npub1yourpublickey...",
    "domain":   "https://yourapp.com"
  }'
```

A successful response returns the Nostr event ID of the published NIP-33 record:

```json
{ "ok": true, "event": "abc123...", "published": 3, "total": 3 }
```

### 4. Integrate `nostr-bridge.js` into your app

For a self-hosted signer, pass `bunkerOrigin` (and `registrarUrl` if the signer gets its root pubkey from your registrar). Without them, the bridge uses the hosted signer and registrar.

```html
<!-- In your parent app's <head> -->
<script src="https://cdn.yourdomain.com/nostr-bridge.js"></script>
<script>
  NostrBridge.init({
    clientId: "YOUR_WEB3AUTH_CLIENT_ID",
    bunkerOrigin: "https://bunker.yourdomain.com", // your self-hosted signer
    registrarUrl: "https://nostr-shard-registrar.<account>.workers.dev",
    layout: "floating", // or "in-place"
    buttonSize: "standard", // or "large_social_grid"
    forceIframe: false, // true = skip native extension check
    poweredBy: true, // false = hide the "Powered by nostr-shard-signer" link on the sign-in sheet
  });
</script>
```

`window.nostr` is installed once `NostrBridge.init()` resolves (await it). Calls made before the iframe reports its auth state are queued automatically.

```js
// After `await NostrBridge.init(...)` — queued if the iframe hasn't reported AUTH_STATE yet
const pubkey = await window.nostr.getPublicKey();
const signed = await window.nostr.signEvent({
  kind: 1,
  content: "Hello Nostr!",
  tags: [],
  created_at: Math.floor(Date.now() / 1000),
});
```

---

## Updating Allowed Domains

**Option A — Portal UI** (recommended)

Open the developer portal, switch to the **Update Domains** tab, enter your `clientId`, add/remove domains, and click **Sign & Update**. The portal fetches the nonce, prompts your Nostr extension to sign it (kind 27235), and submits the proof — no terminal needed.

**Option B — curl**

```bash
# Phase 1: request a nonce
NONCE=$(curl -s -X POST https://<worker>/update \
  -H "Content-Type: application/json" \
  -d '{"clientId":"YOUR_CLIENT_ID","npub":"npub1..."}' | jq -r .nonce)

# Phase 2: sign the nonce with your Nostr key (using nak or any NIP-01 signer)
SIGNED=$(nak event --kind 27235 --content "$NONCE" --sec <your_nsec>)

# Submit the update with the signed event
curl -X POST https://<worker>/update \
  -H "Content-Type: application/json" \
  -d "{
    \"clientId\":    \"YOUR_CLIENT_ID\",
    \"nonce\":       \"$NONCE\",
    \"domains\":     [\"https://yourapp.com\", \"https://staging.yourapp.com\"],
    \"signedEvent\": $SIGNED
  }"
```

The nonce is stored in `CHALLENGES_KV` with a 5-minute TTL and deleted after use.

---

## Communication Protocol

### Versioning

The bridge passes its protocol version in the iframe URL (`signer.html?protocol=1&…`; bridges from before the handshake send none and speak 1). The signer answers `{ type: "SIGNER_HELLO", protocol }`, or, for a version it doesn't support, shows an error and posts `SIGNER_ERROR` with code `PROTOCOL_UNSUPPORTED`. Bump `PROTOCOL_VERSION` in `nostr-bridge.js` on breaking message changes, and keep the old version in the signer's `SUPPORTED_PROTOCOLS` while bridges speaking it may still be pinned or cached (jsDelivr, copies, older npm loaders on self-hosted signers).

Separately, `NostrBridge.apiVersion` versions the page-facing API that `nostr-bridge.d.ts` describes; the npm package's loader warns when it differs from the version its types describe.

### UI/State (custom schema, iframe → parent)

| Message                                                        | When sent                              |
| -------------------------------------------------------------- | -------------------------------------- |
| `{ type: "SIGNER_HELLO", protocol: number }`                   | On load, once the protocol is accepted |
| `{ type: "AUTH_STATE", loggedIn: bool, pubkey: string\|null }` | On iframe load (passive session check) |
| `{ type: "AUTH_SUCCESS", pubkey: string }`                     | After user completes OAuth flow        |
| `{ type: "RESIZE", state: "button"\|"avatar"\|"modal" }`       | On every view transition               |

### UI control (custom schema, parent → iframe)

| Message                  | Sent by                 | Effect                                       |
| ------------------------ | ----------------------- | -------------------------------------------- |
| `{ type: "OPEN_LOGIN" }` | `NostrBridge.login()`   | Opens the sign-in modal (as the button does) |
| `{ type: "LOGOUT" }`     | `NostrBridge.logout()`  | Logs out of Web3Auth, replies `AUTH_STATE`   |

### Crypto requests (NIP-46 RPC, parent → iframe)

```jsonc
// Request
{ "id": "req_0", "method": "sign_event", "params": ["<stringified_unsigned_event>"] }

// Success response
{ "id": "req_0", "result": "<stringified_signed_event>", "error": null }

// Rejection
{ "id": "req_0", "result": null, "error": "User rejected request" }
```

Supported methods: `get_public_key`, `sign_event`, `nip04_encrypt`, `nip04_decrypt`, `nip44_encrypt`, `nip44_decrypt`

### Auto-approve policy

Approval settings are stored per host site. Confirmations are queued and shown one at a time.

| Action                                                                                                   | Behaviour                                 |
| -------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| Kinds 1, 7, 1111, 30818, 10003, 30003, 31922, 31923, 30078                                               | Auto-approved by default (user can untick) |
| Kind 27235 (NIP-98) for `https://nostr.build` and its subdomains                                         | Auto-approved by default (user can untick) |
| Kinds 6, 42                                                                                              | Confirmation modal (user can tick)        |
| Kind 0 (profile), 3 (follows), 10002 (relays), 5 (deletion), 27235 for other hosts                       | Always a confirmation modal               |
| Other kinds (zaps, DMs, unknown kinds), `nip04_encrypt`, any decrypt                                     | Confirmation modal                        |
| `get_public_key`, `nip44_encrypt`                                                                        | No confirmation                           |

---

## Registrar API Reference

### `POST /register`

Claim a new clientId. First-come, first-served. The same npub can add more domains idempotently. The domain and the signer origin (`SIGNER_ORIGIN`, default `https://saintego.github.io`) must be in the clientId's Web3Auth Allowlist URLs; `/update` checks every domain the same way. If Web3Auth's config endpoint can't be reached, the request is accepted without that check and the response carries a `note` saying so.

```jsonc
// Request
{ "clientId": "string", "npub": "npub1...", "domain": "https://app.example.com" }

// 201 Created
{ "ok": true, "event": "<nostr_event_id>", "published": 3, "total": 3 }

// 403 — domain or signer origin missing from the Web3Auth allowlist
{ "error": "Add https://app.example.com to this clientId's Allowlist URLs in the Web3Auth dashboard (Project Settings → Domains), then retry." }

// 404 — no Web3Auth Sapphire Mainnet project with this clientId
{ "error": "Web3Auth has no Sapphire Mainnet project with this clientId. ..." }

// 409 Conflict — already claimed by different npub
{ "error": "clientId is already claimed by a different npub" }
```

### `POST /update` (two-phase)

**Phase 1** — request a nonce (omit `nonce` and `signedEvent`):

```jsonc
// Request
{ "clientId": "string", "npub": "npub1..." }

// Response
{ "ok": true, "nonce": "<64 hex chars>", "expiresIn": 300 }
```

**Phase 2** — submit the update with proof:

```jsonc
// Request
{
  "clientId":   "string",
  "nonce":      "<64 hex chars from Phase 1>",
  "domains":    ["https://app.example.com"],
  "signedEvent": { /* signed NIP-01 kind:27235 event with content = nonce */ }
}

// Response
{ "ok": true, "event": "<nostr_event_id>", "domains": [...], "published": 3, "total": 3 }
```

Nonces are stored with a 5-minute TTL and consumed on first use.

---

### Registry sync, `GET /health` and `POST /sync`

Relays don't sync with each other and can lose data, so the registrar keeps every registry event it publishes in `REGISTRY_KV` as well. A daily cron (`[triggers]` in `wrangler.toml`) reads all relays in `RELAY_URLS`, keeps the newest event per clientId, stores any event missing from KV, and re-sends the signed event to every relay that lacks it. Adding a relay to `RELAY_URLS` therefore fills it on the next run.

`GET /health` returns the last run's report:

```jsonc
{
  "status": "ok",                 // "degraded": a registration is on fewer than 3 relays, or under half the relays are reachable
  "checkedAt": "2026-09-25T07:44:43.716Z",
  "registrations": 5,
  "kvBackfilled": 0,              // events found on relays but not yet in KV
  "relaysReachable": "5/5",
  "relays": [{ "url": "wss://nos.lol", "reachable": true, "missing": 2, "repaired": 2 }],
                                  // "rejected": ["<relay's reason>"] when a relay refused a re-send,
                                  // "dropped": n when it answered OK but doesn't return the event
  "underReplicated": []           // [{ clientId, copies }]
}
```

`POST /sync` runs the sync immediately (at most once every 5 minutes) and returns the same report. Neither endpoint needs auth; a sync only re-sends events the root key already signed.

```bash
# Hosted registrar; self-hosted: use your Worker URL
curl -s -X POST https://nostr-shard-registrar.nostr-shard-signer.workers.dev/sync   # repair relays now
curl -s https://nostr-shard-registrar.nostr-shard-signer.workers.dev/health         # last report
```

**When to run it:** the widget shows only the Nostr-signer button (no Web3Auth sign-in) and the host page's console logs `DOMAIN_NOT_REGISTERED` for a domain you did register. The signer found the registration on none of the registry relays it could reach, usually because the relays that held it dropped it or are down. Run `POST /sync`, then check `underReplicated` is empty.

**Choosing relays:** a relay that always reports `missing` with `repaired: 0`, or lists `rejected` reasons or `dropped`, doesn't keep these events; one that stays `reachable: false` is down. Replace either in `RELAY_URLS` (and `DEFAULT_REGISTRY_RELAYS` in `bunker/src/lib/nostr.ts`). Dead relays also slow the signer: it waits for every relay (up to 8 s) before the final authorization answer.

## Production Hardening Checklist

**One-time setup**

- [ ] Replace `__ROOT_PUBKEY_HEX__` in `signer.html`
- [ ] Run `wrangler secret put ROOT_PRIVATE_KEY_HEX` — never commit the private key
- [ ] Create both KV namespaces (`REGISTRY_KV`, `CHALLENGES_KV`) and update `wrangler.toml` IDs
- [ ] Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` as GitHub repository secrets
- [ ] Enable GitHub Pages (Settings → Pages → Source: GitHub Actions)
- [ ] Update `REGISTRAR_URL` in `portal/index.html` to your deployed Worker URL

**After first deploy**

- [ ] Pass `bunkerOrigin` (your Pages `signer.html` URL) and `registrarUrl` to `NostrBridge.init()` — otherwise the hosted signer is used
- [ ] Add SRI hashes to CDN `<script>` tags in `signer.html`
- [ ] Restrict `Access-Control-Allow-Origin` in `registrar-worker.js` to your admin origins
- [ ] Configure `REGISTRY_RELAYS` in `signer.html` to relays you control or trust
- [ ] Set up Cloudflare Rate Limiting rules on the registrar endpoints
- [ ] Configure your Web3Auth dashboard verifiers to match your `clientId`

## 🚧 Known Issues & TODOs

If you are contributing or using this in production, please be aware of the following architectural quirks currently being worked on:

- [ ] **Extension Override Lockout:** If a user has a NIP-07 extension installed (like Alby), the bridge detects it and completely skips the Web3Auth iframe. Currently, if an Alby user _wants_ to log in with Google, there is no UI toggle to let them do so.
  - **Workaround:** Parent apps must manually implement two login buttons and call `NostrBridge.init({ forceIframe: true })` to bypass the extension check.

---

## License

MIT — see [LICENSE](LICENSE).

<sub>Nostr login with Google, Apple and X · Nostr OAuth / social login · NIP-07 without a browser extension · `window.nostr` for any website · NIP-46 bunker login · MPC Nostr keys · Nostr onboarding for new users · #nostr #oauth #nip07 #nip46 #web3auth</sub>
