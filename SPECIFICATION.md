# nostr-shard-signer — Technical Specification

## Security Model: Key Isolation

Your Nostr private key (nsec) is held exclusively inside a sandboxed cross-origin iframe hosted on `bunker.yourdomain.com`. It is never passed to, accessible by, or visible in the memory of the parent application page.

- **Not logged in:** Key material is fully disassembled by Web3Auth's MPC infrastructure and distributed across threshold key shares — no complete key exists anywhere until you authenticate again.
- **Logged in:** The reconstructed key lives only in the iframe's isolated JavaScript context. The browser's Same-Origin Policy makes this context physically unreachable from the parent page's code, regardless of what scripts the parent page runs.

> For users who require zero client-side key reconstruction, use [nsec.app](https://nsec.app) or a self-hosted NIP-46 bunker.

---

## 1. System Overview

The goal is to provide a "Web2-style" social login (Google/Email) for a Nostr app without exposing the user's private key (nsec) to the parent application's memory.

| Component        | Role                                                                                                                                                                                                                                                                                                                                               |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **The Sandbox**  | The private key is extracted and held only inside a secure universal iframe hosted on a central origin (`bunker.yourdomain.com`).                                                                                                                                                                                                                  |
| **The Registry** | The iframe prevents domain-spoofing by querying a hardcoded Root Pubkey's NIP-33 events to verify if the parent's domain is authorized to use the provided Web3Auth `clientId`.                                                                                                                                                                    |
| **The Bridge**   | The parent app uses a comprehensive JS bundle that natively integrates `window.nostr.js` or `nostr-login`. Standard extensions (Alby), mobile signers (Amber), and remote bunkers (NIP-46) are all supported alongside the hidden iframe bunker. The bundle acts as a traffic router, forwarding signature requests to whichever signer is active. |
| **The UI**       | The iframe manages its own visual state, communicating with the parent script to resize its container based on user interaction.                                                                                                                                                                                                                   |

---

## 2. Component Architecture

### Component A — The Parent Wrapper (`nostr-bridge.js`)

**Responsibility:** Injects the iframe, manages iframe CSS sizing based on messages, and intercepts `window.nostr` calls.

**Logic Flow:**

1. **Initialization** is fully parameterized by the developer:

   ```js
   NostrBridge.init({
     clientId: "YOUR_WEB3_ID",
     forceIframe: false,
     layout: "floating" | "in-place",
     buttonSize: "standard" | "large_social_grid",
   });
   ```

2. By default, checks if `window.nostr` exists. If yes, delegates to `nostr-login` or the native extension.
   - Implements a **fallback timeout** (e.g. 5 seconds) — if the local extension is locked/unresponsive, the proxy falls back to injecting the iframe bunker or rejects with a clear error.
   - If `forceIframe: true`, skips the extension check entirely.

3. Injects the iframe:

   ```html
   <iframe
     id="nostr-signer-iframe"
     sandbox="allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-forms"
     allow="clipboard-write"
     src="https://bunker.yourdomain.com?clientId=${config.clientId}"
   >
   </iframe>
   ```

   > **Note:** `allow-same-origin` is required so `event.origin` is not `"null"` during validation. `allow-popups-to-escape-sandbox` is necessary for Web3Auth's OAuth popup flow (Google login), but means popups inherit the iframe's origin context.

4. **Proxy injection:** `window.nostr` is injected synchronously the millisecond the page loads.

5. **Queue Management:**
   - The iframe sends `AUTH_STATE` on load (`loggedIn: true/false`).
   - **State unknown (loading):** Proxy queues the Promise.
   - **`loggedIn: false`:** Proxy immediately rejects or returns null (prevents infinite loading screens).
   - **`loggedIn: true` / `AUTH_SUCCESS` received:** Proxy resolves the queue.

6. **Routing Methods:** Intercept `window.nostr.signEvent`, `nip04.encrypt/decrypt`, and `nip44.encrypt/decrypt`. Wrap in Promises, format as NIP-46 RPC requests, send via `postMessage`, and resolve when the iframe replies.

7. **CSS states** (Button, Avatar, Modal) are dynamically sized based on the developer's `layout` config.

---

### Component B — The Secure Bunker (`signer.html`)

**Responsibility:** Handles Web3Auth/OAuth login, holds the raw nsec in memory, signs Nostr events using `nostr-tools`, and renders the UI (Button → Avatar → Profile).

**Strict Message Validation:**

- Never accept messages where `event.origin === "null"`.
- **Parent:** validate `event.source === document.getElementById('nostr-signer-iframe').contentWindow`.
- **Iframe:** validate `event.source === window.parent`.

**Logic Flow:**

1. **Registry Check** — Before rendering anything:
   - Read the parent domain from `event.origin` or `document.ancestorOrigins`.
   - Connect to a relay and query:
     ```json
     {
       "authors": ["YOUR_ROOT_PUBKEY"],
       "kinds": [30078],
       "#d": ["${clientId}"]
     }
     ```
   - Parse event content. If parent domain is in `allowed_domains`, proceed. Otherwise halt with: `"Domain not authorized for this Client ID."`.
   - Use in-memory session caching and a dedicated relay for speed.

2. **Initialization:** Initialize Web3Auth using the `clientId` from URL params. Render configured social login options (Google, Apple, Twitter, Email/Passkey, etc.).

3. **On login success:**
   - Extract private key: `web3auth.provider.request({ method: "private_key" })`.
   - Derive `npub`/hex public key via `nostr-tools`.
   - Send `AUTH_SUCCESS` to the parent with the public key.
   - Update DOM to show user avatar.
     > `AUTH_SUCCESS` is sent after a user actively completes the OAuth flow, distinct from `AUTH_STATE` which is sent passively on iframe load.

4. **Cryptographic Request Handling:** Listen for NIP-46 RPC `postMessage` calls. Process with `nostr-tools` and the isolated private key. Return NIP-46 response objects.

5. **Auto-Approve Policy:**

   | Action                                | Behaviour        |
   | ------------------------------------- | ---------------- |
   | Kind 1 (notes), Kind 7 (reactions)    | ✅ Auto-approved |
   | Kind 0 (profile update)               | ⚠️ Prompt user   |
   | Kind 4 / Kind 44 (DMs)                | ⚠️ Prompt user   |
   | Kind 9734 (Zaps)                      | ⚠️ Prompt user   |
   | Unknown custom kinds                  | ⚠️ Prompt user   |
   | Any `nip04_decrypt` / `nip44_decrypt` | ⚠️ Prompt user   |

   For prompt-required actions: trigger `RESIZE → "modal"`, show confirmation UI ("Allow app to read direct messages?", "Approve Zap?", etc.), and only process and return if the user clicks **Approve**.

6. **Profile Modal UI** (shown when user clicks their avatar):
   - View and copy `npub` and `nsec` (Export Secret Key).
   - Edit Nostr metadata: Username, Avatar URL, About, LNURL/Zap address.
   - Sign NIP-01 metadata event locally and broadcast to default relays.

---

### Component C — The Registrar Service (`registrar-worker.js`)

**Responsibility:** A lightweight backend API to securely bind developers' Client IDs to their domains, preventing update-attacks.

**Logic Flow:**

1. **`POST /register`**
   - Accepts `clientId`, `npub`, `domain`.
   - Checks KV store — if `clientId` is already claimed by a different npub, reject.
   - If valid, format and publish a NIP-33 event:
     ```json
     {
       "kind": 30078,
       "tags": [
         ["d", "clientId"],
         ["p", "<registrant_npub>"]
       ],
       "content": "{\"allowed_domains\": [\"domain\"]}"
     }
     ```
   - Sign with server's root private key and broadcast to Nostr relays.

2. **`POST /challenge`**
   - Generates a random nonce (expires in 5 minutes).
   - Returns nonce for the developer to sign as proof of ownership.

3. **`POST /update`**
   - Accepts `clientId`, `domains[]`, and `proofEvent` (a signed NIP-01 kind:27235 event whose content is the nonce from `/challenge`).
   - Verifies the signature proves ownership of the `p`-tagged npub.
   - Publishes updated NIP-33 record (replaces old one via `d` tag).

---

## 3. Communication Protocol

### A. UI & State Control (Custom Schema, Iframe → Parent)

> `AUTH_STATE` and `AUTH_SUCCESS` are session lifecycle events, not RPC calls — they intentionally use this custom schema rather than NIP-46.

```jsonc
// Sent on iframe load (passive session check)
{ "type": "AUTH_STATE", "loggedIn": true, "pubkey": "hex_or_null" }

// Sent after user actively completes OAuth flow
{ "type": "AUTH_SUCCESS", "pubkey": "hex_string" }

// Sent on every view transition
{ "type": "RESIZE", "state": "button" | "avatar" | "modal" }
```

### B. Cryptographic Operations (NIP-46 RPC Standard)

NIP-46 format: stringified arrays for `params`, stringified objects for `result`.

**Parent → Iframe (Requests):**

```jsonc
{ "id": "req_0", "method": "get_public_key",  "params": [] }
{ "id": "req_1", "method": "sign_event",       "params": ["<stringified_unsigned_event>"] }
{ "id": "req_2", "method": "nip04_encrypt",    "params": ["<recipient_hex>", "<plaintext>"] }
{ "id": "req_3", "method": "nip04_decrypt",    "params": ["<sender_hex>", "<ciphertext>"] }
{ "id": "req_4", "method": "nip44_encrypt",    "params": ["<recipient_hex>", "<plaintext>"] }
{ "id": "req_5", "method": "nip44_decrypt",    "params": ["<sender_hex>", "<ciphertext>"] }
```

**Iframe → Parent (Responses):**

```jsonc
// Success
{ "id": "req_1", "result": "<stringified_signed_event_or_string>", "error": null }

// Error / Rejected
{ "id": "req_1", "result": null, "error": "User rejected request" }
```

> **Security Rule:** All `window.addEventListener("message")` handlers MUST validate `event.origin` against expected domains and perform `event.source` checks. Reject `event.origin === "null"` unconditionally.

---

## 4. Web3 Signer Comparison (2026)

> The provider must allow **silent programmatic private key extraction** so `nostr-tools` can run Schnorr signatures without external UI popups.

| Feature                     | Web3Auth ⭐                                  | Turnkey                                                    | Dynamic.xyz                                 | Arcana Auth                    | Privy                            | Moralis               |
| --------------------------- | -------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------- | ------------------------------ | -------------------------------- | --------------------- |
| **Underlying Tech**         | MPC                                          | Secure Enclave (TEE)                                       | MPC / Embedded Wallets                      | MPC                            | TEE / Stripe Crypto              | N/A (Shifted to APIs) |
| **Silent Key Extraction**   | ✅ Flawless `private_key` extraction via RPC | ✅ Programmatic via `exportPrivateKey()` to secure iframes | ❌ Forces own UI flow (`initExportProcess`) | ❌ Extracts via own UI widgets | ❌ Actively blocks silent export | N/A                   |
| **Nostr Signature Support** | Needs `nostr-tools` polyfill                 | Needs `nostr-tools` polyfill                               | Needs `nostr-tools` polyfill                | Needs `nostr-tools` polyfill   | Needs polyfill                   | N/A                   |
| **Custom Iframe UI**        | ✅ Perfect — 100% your UI                    | ✅ Perfect — pure API/backend                              | ❌ Enforces own UI overlays                 | ❌ Enforces own UI widgets     | ❌ Enforces own UI overlays      | N/A                   |
| **Free Tier**               | 1,000 MAW                                    | First 25 signatures                                        | 500 MAW                                     | 500 MAW                        | 499 MAU                          | N/A                   |
| **Pricing**                 | $69/mo                                       | $0.10/signature                                            | ~$249/mo                                    | $99/mo                         | $299/mo                          | N/A                   |

### Verdict

**Web3Auth** — Best choice. One of the few providers that treats the developer as a trusted entity who can programmatically request the raw secp256k1 private key out of the SDK in the background. Mandatory for running `nostr-tools` Schnorr signatures without external UI popups.

**Turnkey** — Runner-up for power users. Entirely API-driven; can export private keys directly into iframes via `@turnkey/http`. Steeper learning curve (managing "Stampers" and API policies) and charges per signature, which can get expensive in a high-activity Nostr app.

**Dynamic, Privy, Arcana** — Fight this architecture. Great for standard Ethereum apps, but they want to own the UI and purposefully lock down silent private key extraction. Triggering export forces a proprietary modal popup that breaks the 3-State (Button → Avatar → Profile) iframe flow.

**Moralis** — No longer viable. Deprecated native Auth tools to become a data provider (RPC nodes, indexers) and now wraps Web3Auth/Wagmi under the hood.
