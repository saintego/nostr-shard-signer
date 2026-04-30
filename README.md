# nostr-shard-signer

A cross-origin iframe authentication system for Nostr. Bridges a Web3Auth MPC OAuth provider into a standard `window.nostr` object using a sandboxed iframe — your private key never touches the parent page's memory.

## Security Model

| Threat | Mitigation |
|--------|-----------|
| Parent page JS reading your nsec | Key lives only in a cross-origin iframe; Same-Origin Policy makes it unreachable |
| Browser extension / XSS on parent page | Same isolation — the iframe context is physically separate |
| Domain spoofing to steal Web3Auth quota | NIP-33 registry on Nostr validates every (clientId, domain) pair before the iframe renders |
| Rogue iframe injected by attacker | `event.source === window.parent` check + `_parentOrigin` derived from `document.ancestorOrigins` (not URL params) |
| null-origin postMessage attacks | All `window.addEventListener("message")` handlers reject `event.origin === "null"` unconditionally |

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
│  │ <iframe src="bunker.yourdomain.com">  │  │
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
│  REGISTRY_KV: claim:{clientId}              │
│  CHALLENGES_KV: challenge nonces (TTL 5m)   │
│  Publishes kind:30078 events to Nostr relays│
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
├── nostr-bridge.js        # Parent wrapper — injects iframe, proxies window.nostr
├── bunker/
│   └── signer.html        # Secure bunker — holds key, signs events, renders UI
└── registrar/
    ├── registrar-worker.js  # Cloudflare Worker — NIP-33 registry API
    ├── wrangler.toml        # Worker configuration
    └── package.json
```

---

## Deployment

### 1. Generate the root keypair

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

### 2. Configure `signer.html`

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

### 3. Deploy the bunker (signer.html)

Host `bunker/signer.html` on any static HTTPS host. The origin must be consistent — every parent app will iframe this URL.

**GitHub Pages example:**
```bash
# From the bunker/ directory:
git subtree push --prefix bunker origin gh-pages
# Serve at: https://<user>.github.io/nostr-shard-signer/signer.html
```

**Vercel example:**
```bash
cd bunker && vercel --prod
```

Note the deployed URL — it must be passed as `bunkerOrigin` when calling `NostrBridge.init()` (required, no default).

### 4. Deploy the Cloudflare Worker

```bash
cd registrar

# Install dependencies
npm install

# Create both KV namespaces
wrangler kv:namespace create "REGISTRY_KV"
# → Copy the returned id into wrangler.toml [[kv_namespaces]] binding = "REGISTRY_KV"
wrangler kv:namespace create "CHALLENGES_KV"
# → Copy the returned id into wrangler.toml [[kv_namespaces]] binding = "CHALLENGES_KV"

# Store the private key as a secret (never commit it)
wrangler secret put ROOT_PRIVATE_KEY_HEX
# → Paste the hex private key when prompted

# Deploy
npm run deploy
# → Worker live at: https://nostr-shard-registrar.<account>.workers.dev
```

### 5. Register your first clientId

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

### 6. Integrate `nostr-bridge.js` into your app

`bunkerOrigin` is **required** — NostrBridge throws if it is omitted.

```html
<!-- In your parent app's <head> -->
<script src="https://cdn.yourdomain.com/nostr-bridge.js"></script>
<script>
  NostrBridge.init({
    clientId:    "YOUR_WEB3AUTH_CLIENT_ID",
    bunkerOrigin:"https://bunker.yourdomain.com",  // required
    layout:      "floating",   // or "in-place"
    buttonSize:  "standard",   // or "large_social_grid"
    forceIframe: false,        // true = skip native extension check
  });
</script>
```

`window.nostr` is injected synchronously, so calls made before the iframe loads are automatically queued.

```js
// Works immediately — queued if iframe hasn't reported AUTH_STATE yet
const pubkey = await window.nostr.getPublicKey();
const signed = await window.nostr.signEvent({ kind: 1, content: "Hello Nostr!", tags: [], created_at: Math.floor(Date.now()/1000) });
```

---

## Updating Allowed Domains

To add or remove domains from a registered clientId, use the two-phase `/update` flow:

```bash
# Phase 1: request a nonce (no nonce/signedEvent body → returns challenge)
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

| Message | When sent |
|---------|-----------|
| `{ type: "AUTH_STATE", loggedIn: bool, pubkey: string\|null }` | On iframe load (passive session check) |
| `{ type: "AUTH_SUCCESS", pubkey: string }` | After user completes OAuth flow |
| `{ type: "RESIZE", state: "button"\|"avatar"\|"modal" }` | On every view transition |

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

| Action | Behaviour |
|--------|-----------|
| Kind 1 (notes), Kind 7 (reactions) | Auto-approved |
| Kind 0 (profile), Kind 9734 (zaps), Kind 4/44 (DMs), unknown kinds | Confirmation modal |
| Any decrypt operation | Confirmation modal |

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

- [ ] Replace `__ROOT_PUBKEY_HEX__` in `signer.html`
- [ ] Pass `bunkerOrigin` (deployed signer.html URL) to `NostrBridge.init()` — it is required
- [ ] Run `wrangler secret put ROOT_PRIVATE_KEY_HEX` — never commit the private key
- [ ] Create both KV namespaces (`REGISTRY_KV`, `CHALLENGES_KV`) and update `wrangler.toml` IDs
- [ ] Add SRI hashes to CDN `<script>` tags in `signer.html`
- [ ] Restrict `Access-Control-Allow-Origin` in `registrar-worker.js` to your admin origins
- [ ] Configure `REGISTRY_RELAYS` in `signer.html` to relays you control or trust
- [ ] Set up Cloudflare Rate Limiting rules on the registrar endpoints
- [ ] Configure your Web3Auth dashboard verifiers to match your `clientId`

---

## License

MIT
