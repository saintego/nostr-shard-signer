# nostr-shard-signer

A cross-origin iframe authentication system for Nostr. Bridges a Web3Auth MPC OAuth provider into a standard `window.nostr` object using a sandboxed iframe — your private key never touches the parent page's memory.

## Security Model

| Threat                                  | Mitigation                                                                                                        |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Parent page JS reading your nsec        | Key lives only in a cross-origin iframe; Same-Origin Policy makes it unreachable                                  |
| Browser extension / XSS on parent page  | Same isolation — the iframe context is physically separate                                                        |
| Domain spoofing to steal Web3Auth quota | NIP-33 registry on Nostr validates every (clientId, domain) pair before the iframe renders                        |
| Rogue iframe injected by attacker       | `event.source === window.parent` check + `_parentOrigin` derived from `document.ancestorOrigins` (not URL params) |
| null-origin postMessage attacks         | All `window.addEventListener("message")` handlers reject `event.origin === "null"` unconditionally                |

> **For users who require zero client-side key reconstruction**, use [nsec.app](https://nsec.app) or a self-hosted NIP-46 bunker instead.

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

## File Structure

```
nostr-shard-signer/
├── nostr-bridge.js          # Parent wrapper — injects iframe, proxies window.nostr
├── bunker/
│   └── signer.html          # Secure bunker — holds key, signs events, renders UI
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

#### b. Configure `signer.html`

Replace the placeholder constant in `bunker/signer.html`:

```js
const ROOT_PUBKEY_HEX = "__ROOT_PUBKEY_HEX__";
// → your actual hex public key, e.g.:
const ROOT_PUBKEY_HEX = "a3b2...";
```

Optionally adjust:

- `REGISTRY_RELAYS` — array of relays that host your NIP-33 events
- `PUBLISH_RELAYS` — relays to broadcast profile updates to

`signer.html` uses ESM (`<script type="module">`) with nostr-tools v2 and Web3Auth modal@9 loaded from CDN — no bundler needed.

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

`bunkerOrigin` is **required** — NostrBridge throws if it is omitted.

```html
<!-- In your parent app's <head> -->
<script src="https://cdn.yourdomain.com/nostr-bridge.js"></script>
<script>
  NostrBridge.init({
    clientId: "YOUR_WEB3AUTH_CLIENT_ID",
    bunkerOrigin: "https://bunker.yourdomain.com", // required
    layout: "floating", // or "in-place"
    buttonSize: "standard", // or "large_social_grid"
    forceIframe: false, // true = skip native extension check
  });
</script>
```

`window.nostr` is injected synchronously, so calls made before the iframe loads are automatically queued.

```js
// Works immediately — queued if iframe hasn't reported AUTH_STATE yet
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

### UI/State (custom schema, iframe → parent)

| Message                                                        | When sent                              |
| -------------------------------------------------------------- | -------------------------------------- |
| `{ type: "AUTH_STATE", loggedIn: bool, pubkey: string\|null }` | On iframe load (passive session check) |
| `{ type: "AUTH_SUCCESS", pubkey: string }`                     | After user completes OAuth flow        |
| `{ type: "RESIZE", state: "button"\|"avatar"\|"modal" }`       | On every view transition               |

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

| Action                                                             | Behaviour          |
| ------------------------------------------------------------------ | ------------------ |
| Kind 1 (notes), Kind 7 (reactions)                                 | Auto-approved      |
| Kind 0 (profile), Kind 9734 (zaps), Kind 4/44 (DMs), unknown kinds | Confirmation modal |
| Any decrypt operation                                              | Confirmation modal |

---

## Registrar API Reference

### `POST /register`

Claim a new clientId. First-come, first-served. The same npub can add more domains idempotently.

```jsonc
// Request
{ "clientId": "string", "npub": "npub1...", "domain": "https://app.example.com" }

// 201 Created
{ "ok": true, "event": "<nostr_event_id>", "published": 3, "total": 3 }

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

## Production Hardening Checklist

**One-time setup**

- [ ] Replace `__ROOT_PUBKEY_HEX__` in `signer.html`
- [ ] Run `wrangler secret put ROOT_PRIVATE_KEY_HEX` — never commit the private key
- [ ] Create both KV namespaces (`REGISTRY_KV`, `CHALLENGES_KV`) and update `wrangler.toml` IDs
- [ ] Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` as GitHub repository secrets
- [ ] Enable GitHub Pages (Settings → Pages → Source: GitHub Actions)
- [ ] Update `REGISTRAR_URL` in `portal/index.html` to your deployed Worker URL

**After first deploy**

- [ ] Pass `bunkerOrigin` (your Pages `signer.html` URL) to `NostrBridge.init()` — it is required
- [ ] Add SRI hashes to CDN `<script>` tags in `signer.html`
- [ ] Restrict `Access-Control-Allow-Origin` in `registrar-worker.js` to your admin origins
- [ ] Configure `REGISTRY_RELAYS` in `signer.html` to relays you control or trust
- [ ] Set up Cloudflare Rate Limiting rules on the registrar endpoints
- [ ] Configure your Web3Auth dashboard verifiers to match your `clientId`

---

## License

MIT
