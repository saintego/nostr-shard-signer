/**
 * registrar-worker.js
 *
 * Cloudflare Worker — NIP-33 Root Pubkey Registry
 *
 * Securely binds Web3Auth clientIds to authorized domains and publishes
 * the binding as a NIP-33 (kind:30078) event signed by the server's root keypair.
 *
 * Required Cloudflare bindings (set via wrangler.toml + `wrangler secret put`):
 *   ROOT_PRIVKEY_HEX  — 64-char hex private key (kept as a secret, never in code)
 *   KV_NAMESPACE      — KV namespace binding
 *   RELAY_URLS        — comma-separated relay WebSocket URLs (env var)
 *
 * Endpoints:
 *   POST /register   — claim a new clientId → domain binding
 *   POST /challenge  — request a nonce to prove ownership of a registered npub
 *   POST /update     — update allowed_domains after proving ownership
 *
 * Security model:
 *   - /register is open: anyone can claim an unclaimed clientId.
 *     If a clientId is already claimed by a *different* pubkey, the request is rejected.
 *   - /update requires a cryptographic ownership proof (signed nonce, NIP-98 style).
 *   - Nonces are one-time-use and expire after 5 minutes.
 *   - All domain inputs are normalised to their HTTPS origin to prevent bypass via path tricks.
 */

import {
  finalizeEvent,
  verifyEvent,
  nip19,
} from "nostr-tools";

// ── Constants ─────────────────────────────────────────────────────────────────

const KV_PREFIX_CLAIM = "claim:";   // claim:{clientId}  → JSON
const KV_PREFIX_NONCE = "nonce:";   // nonce:{clientId}  → JSON (TTL-bound)
const NONCE_TTL_SEC   = 300;        // 5 minutes
const MAX_DOMAINS     = 50;         // per clientId
const MAX_CLIENT_ID_LEN = 512;

// ── Utility ───────────────────────────────────────────────────────────────────

/** Convert a 64-char lowercase hex string to Uint8Array (32 bytes). */
function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length !== 64 || !/^[0-9a-f]+$/.test(hex)) {
    throw new Error("Invalid 32-byte hex private key");
  }
  const arr = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

/** Decode a bech32 npub to its 32-byte hex pubkey, or return null on failure. */
function npubToHex(npub) {
  if (typeof npub !== "string") return null;
  try {
    const decoded = nip19.decode(npub);
    return decoded.type === "npub" ? decoded.data : null;
  } catch (_) {
    return null;
  }
}

/** Normalise a domain/origin input to an https:// origin string. */
function normalizeDomain(input) {
  if (typeof input !== "string" || !input) return null;
  try {
    const url = new URL(input.startsWith("http") ? input : "https://" + input);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    // We store the full origin (scheme + host + port)
    return url.origin.toLowerCase(); // e.g. "https://app.example.com"
  } catch (_) {
    return null;
  }
}

/** Validate that a hex string is a well-formed 32-byte public key. */
function isValidHexPubkey(str) {
  return typeof str === "string" && /^[0-9a-f]{64}$/.test(str);
}

// ── Response helpers ──────────────────────────────────────────────────────────

const CORS_HEADERS = {
  // PRODUCTION: restrict to your own admin/integration origins, not "*"
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function jsonOk(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function jsonErr(message, status = 400) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function cors204() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

// ── NIP-33 event builder ──────────────────────────────────────────────────────

/**
 * Build and sign a kind:30078 NIP-33 event.
 * @param {Uint8Array}  rootPrivkeyBytes
 * @param {string}      clientId        — NIP-33 d-tag value
 * @param {string}      registrantHex   — hex pubkey of the domain owner (p-tag)
 * @param {string[]}    allowedDomains  — list of normalised origin strings
 */
function buildRegistryEvent(rootPrivkeyBytes, clientId, registrantHex, allowedDomains) {
  return finalizeEvent(
    {
      kind:       30078,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["d", clientId],
        ["p", registrantHex],
      ],
      content: JSON.stringify({ allowed_domains: allowedDomains }),
    },
    rootPrivkeyBytes
  );
}

// ── Relay broadcaster ─────────────────────────────────────────────────────────

/** Publish a signed Nostr event to a single relay via WebSocket. */
function publishToRelay(relayUrl, event) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { try { ws.close(); } catch (_) {} reject(new Error("Timeout")); }, 10_000);
    let ws;
    try {
      ws = new WebSocket(relayUrl);
    } catch (err) {
      clearTimeout(timer);
      reject(err);
      return;
    }
    ws.addEventListener("open",  () => ws.send(JSON.stringify(["EVENT", event])));
    ws.addEventListener("error", () => { clearTimeout(timer); reject(new Error("WebSocket error")); });
    ws.addEventListener("message", (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      if (!Array.isArray(msg) || msg[0] !== "OK") return;
      clearTimeout(timer);
      ws.close();
      // msg[2] is the success boolean; msg[3] is an optional message
      msg[2] !== false ? resolve(msg) : reject(new Error(msg[3] || "Relay rejected event"));
    });
  });
}

/** Broadcast to all configured relays; resolves if at least one succeeds. */
async function broadcastEvent(env, event) {
  const relayUrls = (env.RELAY_URLS || "wss://relay.damus.io")
    .split(",")
    .map((u) => u.trim())
    .filter(Boolean);

  const results = await Promise.allSettled(relayUrls.map((url) => publishToRelay(url, event)));
  const succeeded = results.filter((r) => r.status === "fulfilled").length;

  if (succeeded === 0) {
    const firstError = results.find((r) => r.status === "rejected");
    throw new Error("Failed to publish to any relay: " + (firstError?.reason?.message || "unknown"));
  }
  return { published: succeeded, total: relayUrls.length };
}

// ── KV helpers ────────────────────────────────────────────────────────────────

async function getClaim(env, clientId) {
  const raw = await env.KV_NAMESPACE.get(KV_PREFIX_CLAIM + clientId);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

async function saveClaim(env, clientId, registrantHex, domains) {
  await env.KV_NAMESPACE.put(
    KV_PREFIX_CLAIM + clientId,
    JSON.stringify({ registrantHex, domains })
  );
}

async function saveNonce(env, clientId, nonce, registrantHex) {
  await env.KV_NAMESPACE.put(
    KV_PREFIX_NONCE + clientId,
    JSON.stringify({ nonce, registrantHex, expiresAt: Date.now() + NONCE_TTL_SEC * 1000 }),
    { expirationTtl: NONCE_TTL_SEC }
  );
}

async function getNonce(env, clientId) {
  const raw = await env.KV_NAMESPACE.get(KV_PREFIX_NONCE + clientId);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

async function deleteNonce(env, clientId) {
  await env.KV_NAMESPACE.delete(KV_PREFIX_NONCE + clientId);
}

// ── Route: POST /register ─────────────────────────────────────────────────────
/**
 * Claim a new clientId for a given npub + domain.
 * If the clientId is already claimed by the same npub, the domain is appended
 * (idempotent). If claimed by a *different* npub, the request is rejected with 409.
 *
 * Body: { clientId: string, npub: string, domain: string }
 */
async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonErr("Request body must be valid JSON"); }

  const { clientId, npub, domain } = body;

  // ── Input validation ────────────────────────────────────────────────────────
  if (!clientId || typeof clientId !== "string" || clientId.length > MAX_CLIENT_ID_LEN) {
    return jsonErr("clientId is required and must be a string ≤ " + MAX_CLIENT_ID_LEN + " chars");
  }
  // Disallow characters that could cause KV key collisions
  if (/[:\s]/.test(clientId)) {
    return jsonErr("clientId must not contain colons or whitespace");
  }

  const normalizedDomain = normalizeDomain(domain);
  if (!normalizedDomain) {
    return jsonErr("domain must be a valid HTTPS origin (e.g. https://app.example.com)");
  }

  const registrantHex = npubToHex(npub);
  if (!registrantHex) {
    return jsonErr("npub is invalid");
  }

  // ── Claim check ─────────────────────────────────────────────────────────────
  const existing = await getClaim(env, clientId);

  if (existing) {
    if (existing.registrantHex !== registrantHex) {
      return jsonErr("clientId is already claimed by a different npub", 409);
    }
    // Same owner — add domain if not already present
    if (existing.domains.includes(normalizedDomain)) {
      return jsonOk({ ok: true, message: "Domain already registered for this clientId" });
    }
    if (existing.domains.length >= MAX_DOMAINS) {
      return jsonErr("Maximum number of domains (" + MAX_DOMAINS + ") reached for this clientId");
    }
    existing.domains.push(normalizedDomain);
    const rootPrivkey = hexToBytes(env.ROOT_PRIVKEY_HEX);
    const event       = buildRegistryEvent(rootPrivkey, clientId, registrantHex, existing.domains);
    const broadcast   = await broadcastEvent(env, event);
    await saveClaim(env, clientId, registrantHex, existing.domains);
    return jsonOk({ ok: true, event: event.id, ...broadcast });
  }

  // ── New claim ───────────────────────────────────────────────────────────────
  const rootPrivkey = hexToBytes(env.ROOT_PRIVKEY_HEX);
  const event       = buildRegistryEvent(rootPrivkey, clientId, registrantHex, [normalizedDomain]);
  const broadcast   = await broadcastEvent(env, event);
  await saveClaim(env, clientId, registrantHex, [normalizedDomain]);

  return jsonOk({ ok: true, event: event.id, ...broadcast }, 201);
}

// ── Route: POST /challenge ────────────────────────────────────────────────────
/**
 * Issue a one-time nonce for the owner of a clientId to sign, proving key ownership.
 * The nonce expires after NONCE_TTL_SEC seconds.
 *
 * Body: { clientId: string, npub: string }
 */
async function handleChallenge(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonErr("Request body must be valid JSON"); }

  const { clientId, npub } = body;
  if (!clientId || !npub) return jsonErr("clientId and npub are required");

  const registrantHex = npubToHex(npub);
  if (!registrantHex) return jsonErr("npub is invalid");

  const existing = await getClaim(env, clientId);
  if (!existing)                                    return jsonErr("clientId not found", 404);
  if (existing.registrantHex !== registrantHex)     return jsonErr("npub does not own this clientId", 403);

  // Generate a 32-byte cryptographically random nonce
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = Array.from(nonceBytes).map((b) => b.toString(16).padStart(2, "0")).join("");

  await saveNonce(env, clientId, nonce, registrantHex);

  return jsonOk({ ok: true, nonce, expiresIn: NONCE_TTL_SEC });
}

// ── Route: POST /update ───────────────────────────────────────────────────────
/**
 * Replace the allowed_domains list for an existing clientId, after the caller
 * proves they own the registered npub by submitting a signed nonce event.
 *
 * Body: {
 *   clientId:   string,
 *   domains:    string[],   // complete replacement list
 *   proofEvent: object,     // NIP-01 signed event; kind=27235; content=<nonce>
 * }
 *
 * Proof event requirements:
 *   - pubkey   === registrant npub (hex)
 *   - content  === the nonce returned by /challenge
 *   - kind     === 27235  (NIP-98 HTTP Auth kind)
 *   - created_at within ±5 minutes of server time
 *   - valid Schnorr signature
 */
async function handleUpdate(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonErr("Request body must be valid JSON"); }

  const { clientId, domains, proofEvent } = body;

  if (!clientId || !Array.isArray(domains) || !proofEvent || typeof proofEvent !== "object") {
    return jsonErr("clientId (string), domains (array), and proofEvent (object) are all required");
  }

  // ── Validate domains list ───────────────────────────────────────────────────
  if (domains.length > MAX_DOMAINS) {
    return jsonErr("Too many domains (max " + MAX_DOMAINS + ")");
  }
  const normalizedDomains = [];
  for (const domain of domains) {
    const n = normalizeDomain(domain);
    if (!n) return jsonErr("Invalid domain in list: " + String(domain).slice(0, 100));
    normalizedDomains.push(n);
  }
  // Deduplicate
  const uniqueDomains = [...new Set(normalizedDomains)];

  // ── Fetch claim ─────────────────────────────────────────────────────────────
  const existing = await getClaim(env, clientId);
  if (!existing) return jsonErr("clientId not found", 404);

  // ── Fetch nonce ─────────────────────────────────────────────────────────────
  const nonceRecord = await getNonce(env, clientId);
  if (!nonceRecord) {
    return jsonErr("No active challenge for this clientId. Call POST /challenge first.");
  }
  if (Date.now() > nonceRecord.expiresAt) {
    await deleteNonce(env, clientId);
    return jsonErr("Challenge nonce has expired. Call POST /challenge again.", 410);
  }

  // ── Validate proof event structure ─────────────────────────────────────────
  const { id, pubkey, sig, kind, content, created_at, tags } = proofEvent;
  if (!id || !pubkey || !sig || kind === undefined || content === undefined || !created_at) {
    return jsonErr("proofEvent is missing required NIP-01 fields (id, pubkey, sig, kind, content, created_at)");
  }

  // pubkey must match the registered owner
  if (pubkey !== existing.registrantHex) {
    return jsonErr("proofEvent pubkey does not match the registered npub");
  }

  // Kind must be 27235 (NIP-98 HTTP Auth)
  if (kind !== 27235) {
    return jsonErr("proofEvent must be kind 27235");
  }

  // Timestamp within ±5 minutes
  const ageSec = Math.floor(Date.now() / 1000) - created_at;
  if (ageSec > NONCE_TTL_SEC || ageSec < -30) {
    return jsonErr("proofEvent created_at is outside the acceptable time window (±5 min)");
  }

  // Content must equal the issued nonce exactly
  if (content !== nonceRecord.nonce) {
    return jsonErr("proofEvent content does not match the issued nonce");
  }

  // Cryptographic signature verification
  let signatureValid = false;
  try {
    signatureValid = verifyEvent(proofEvent);
  } catch (_) {
    return jsonErr("proofEvent signature verification threw an error");
  }
  if (!signatureValid) {
    return jsonErr("proofEvent Schnorr signature is invalid");
  }

  // ── Consume nonce (one-time use) ────────────────────────────────────────────
  await deleteNonce(env, clientId);

  // ── Publish updated NIP-33 event ────────────────────────────────────────────
  const rootPrivkey = hexToBytes(env.ROOT_PRIVKEY_HEX);
  const event       = buildRegistryEvent(rootPrivkey, clientId, existing.registrantHex, uniqueDomains);
  const broadcast   = await broadcastEvent(env, event);

  await saveClaim(env, clientId, existing.registrantHex, uniqueDomains);

  return jsonOk({ ok: true, event: event.id, domains: uniqueDomains, ...broadcast });
}

// ── Main fetch handler ────────────────────────────────────────────────────────

export default {
  async fetch(request, env, _ctx) {
    // CORS preflight
    if (request.method === "OPTIONS") return cors204();

    if (request.method !== "POST") {
      return jsonErr("Method not allowed — use POST", 405);
    }

    // Validate that required secrets are configured
    if (!env.ROOT_PRIVKEY_HEX) {
      return jsonErr("Worker misconfiguration: ROOT_PRIVKEY_HEX secret is not set", 500);
    }
    if (!env.KV_NAMESPACE) {
      return jsonErr("Worker misconfiguration: KV_NAMESPACE binding is missing", 500);
    }

    const url = new URL(request.url);

    try {
      switch (url.pathname) {
        case "/register":  return await handleRegister(request, env);
        case "/challenge": return await handleChallenge(request, env);
        case "/update":    return await handleUpdate(request, env);
        default:           return jsonErr("Not found", 404);
      }
    } catch (err) {
      // Unexpected internal errors — log but don't leak stack traces to clients
      console.error("Registrar unhandled error:", err);
      return jsonErr("Internal server error", 500);
    }
  },
};
