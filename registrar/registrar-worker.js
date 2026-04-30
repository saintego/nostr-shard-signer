/**
 * registrar-worker.js
 *
 * Cloudflare Worker — NIP-33 Root Pubkey Registry
 *
 * Securely binds Web3Auth clientIds to authorized domains and publishes
 * the binding as a NIP-33 (kind:30078) event signed by the server's root keypair.
 *
 * Required Cloudflare bindings (set via wrangler.toml + `wrangler secret put`):
 *   ROOT_PRIVATE_KEY_HEX  — 64-char hex private key (kept as a secret, never in code)
 *   REGISTRY_KV           — KV namespace for clientId → domain claims
 *   CHALLENGES_KV         — KV namespace for one-time ownership challenges
 *   RELAY_URLS            — comma-separated relay WebSocket URLs (env var)
 *
 * Endpoints:
 *   POST /register   — claim a new clientId → domain binding
 *   POST /update     — two-phase: (1) issue challenge nonce, (2) verify and update domains
 *
 * Security model:
 *   - /register is open: anyone can claim an unclaimed clientId.
 *     If a clientId is already claimed by a *different* pubkey, the request is rejected.
 *   - /update requires a cryptographic ownership proof (signed nonce, NIP-98 style).
 *   - Nonces are one-time-use and expire after 5 minutes.
 *   - All domain inputs are normalised to their HTTPS origin to prevent bypass via path tricks.
 */

import { finalizeEvent, verifyEvent, nip19 } from "nostr-tools";

// ── Constants ─────────────────────────────────────────────────────────────────

const KV_PREFIX_CLAIM = "claim:"; // claim:{clientId}  → JSON  (in REGISTRY_KV)
const KV_PREFIX_NONCE = "nonce:"; // nonce:{clientId}  → JSON  (in CHALLENGES_KV, TTL-bound)
const NONCE_TTL_SEC = 300; // 5 minutes
const MAX_DOMAINS = 50; // per clientId
const MAX_CLIENT_ID_LEN = 512;

// ── Utility ───────────────────────────────────────────────────────────────────

/** Convert a 64-char lowercase hex string to Uint8Array (32 bytes). */
function hexToBytes(hex) {
  if (
    typeof hex !== "string" ||
    hex.length !== 64 ||
    !/^[0-9a-f]+$/.test(hex)
  ) {
    throw new Error("Invalid 32-byte hex private key");
  }
  const arr = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

/** Decode a bech32 npub to its 32-byte hex pubkey; falls back to raw hex. */
function npubToHex(input) {
  if (typeof input !== "string") return null;
  // Try bech32 npub first
  try {
    const decoded = nip19.decode(input);
    if (decoded.type === "npub") return decoded.data;
  } catch (_) {}
  // Fall back: accept a raw 64-char lowercase hex pubkey
  if (isValidHexPubkey(input)) return input.toLowerCase();
  return null;
}

/**
 * Validate a hostname against RFC-1123 label rules.
 * Blocks bare IPs, localhost, and single-label hostnames.
 */
function isValidDomain(hostname) {
  return /^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/.test(hostname);
}

/** Normalise a domain/origin input to an https:// origin string. */
function normalizeDomain(input) {
  if (typeof input !== "string" || !input) return null;
  try {
    const url = new URL(input.startsWith("http") ? input : "https://" + input);
    if (url.protocol !== "https:") return null; // only HTTPS origins
    if (!isValidDomain(url.hostname)) return null; // block IPs, localhost, bare names
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
  "Access-Control-Allow-Origin": "*",
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
function buildRegistryEvent(
  rootPrivkeyBytes,
  clientId,
  registrantHex,
  allowedDomains,
) {
  return finalizeEvent(
    {
      kind: 30078,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["d", clientId],
        ["p", registrantHex],
      ],
      content: JSON.stringify({ allowed_domains: allowedDomains }),
    },
    rootPrivkeyBytes,
  );
}

// ── Relay broadcaster ─────────────────────────────────────────────────────────

/** Publish a signed Nostr event to a single relay via WebSocket. */
function publishToRelay(relayUrl, event) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      try {
        ws.close();
      } catch (_) {}
      reject(new Error("Timeout"));
    }, 10_000);
    let ws;
    try {
      ws = new WebSocket(relayUrl);
    } catch (err) {
      clearTimeout(timer);
      reject(err);
      return;
    }
    ws.addEventListener("open", () =>
      ws.send(JSON.stringify(["EVENT", event])),
    );
    ws.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error("WebSocket error"));
    });
    ws.addEventListener("message", (e) => {
      let msg;
      try {
        msg = JSON.parse(e.data);
      } catch {
        return;
      }
      if (!Array.isArray(msg) || msg[0] !== "OK") return;
      clearTimeout(timer);
      ws.close();
      // msg[2] is the success boolean; msg[3] is an optional message
      msg[2] !== false
        ? resolve(msg)
        : reject(new Error(msg[3] || "Relay rejected event"));
    });
  });
}

/** Broadcast to all configured relays; resolves as soon as one succeeds. */
async function broadcastEvent(env, event) {
  const relayUrls = (env.RELAY_URLS || "wss://relay.damus.io")
    .split(",")
    .map((u) => u.trim())
    .filter(Boolean);

  await Promise.any(relayUrls.map((url) => publishToRelay(url, event)));
  return { published: 1, total: relayUrls.length };
}

// ── KV helpers (two separate namespaces) ─────────────────────────────────────

async function getClaim(env, clientId) {
  const raw = await env.REGISTRY_KV.get(KV_PREFIX_CLAIM + clientId);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

async function saveClaim(env, clientId, registrantHex, domains) {
  await env.REGISTRY_KV.put(
    KV_PREFIX_CLAIM + clientId,
    JSON.stringify({ registrantHex, domains }),
  );
}

async function saveChallenge(env, clientId, nonce, registrantHex) {
  await env.CHALLENGES_KV.put(
    KV_PREFIX_NONCE + clientId,
    JSON.stringify({ nonce, registrantHex, expiresAt: Date.now() + NONCE_TTL_SEC * 1000 }),
    { expirationTtl: NONCE_TTL_SEC },
  );
}

async function getChallenge(env, clientId) {
  const raw = await env.CHALLENGES_KV.get(KV_PREFIX_NONCE + clientId);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

async function deleteChallenge(env, clientId) {
  await env.CHALLENGES_KV.delete(KV_PREFIX_NONCE + clientId);
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
  try {
    body = await request.json();
  } catch {
    return jsonErr("Request body must be valid JSON");
  }

  const { clientId, npub, domain } = body;

  // ── Input validation ────────────────────────────────────────────────────────
  if (
    !clientId ||
    typeof clientId !== "string" ||
    clientId.length > MAX_CLIENT_ID_LEN
  ) {
    return jsonErr(
      "clientId is required and must be a string ≤ " +
        MAX_CLIENT_ID_LEN +
        " chars",
    );
  }
  // Disallow characters that could cause KV key collisions
  if (/[:\s]/.test(clientId)) {
    return jsonErr("clientId must not contain colons or whitespace");
  }

  const normalizedDomain = normalizeDomain(domain);
  if (!normalizedDomain) {
    return jsonErr(
      "domain must be a valid HTTPS origin for a public FQDN (e.g. https://app.example.com)",
    );
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
      return jsonOk({
        ok: true,
        message: "Domain already registered for this clientId",
      });
    }
    if (existing.domains.length >= MAX_DOMAINS) {
      return jsonErr(
        "Maximum number of domains (" +
          MAX_DOMAINS +
          ") reached for this clientId",
      );
    }
    existing.domains.push(normalizedDomain);
    const rootPrivkey = hexToBytes(env.ROOT_PRIVATE_KEY_HEX);
    const event = buildRegistryEvent(
      rootPrivkey,
      clientId,
      registrantHex,
      existing.domains,
    );
    await saveClaim(env, clientId, registrantHex, existing.domains);
    try {
      const broadcast = await broadcastEvent(env, event);
      return jsonOk({ ok: true, event: event.id, ...broadcast });
    } catch (err) {
      // Roll back the domain addition on broadcast failure
      existing.domains.pop();
      await saveClaim(env, clientId, registrantHex, existing.domains);
      return jsonErr("Failed to broadcast registry event. Please retry: " + err.message, 502);
    }
  }

  // ── New claim ───────────────────────────────────────────────────────────────
  const rootPrivkey = hexToBytes(env.ROOT_PRIVATE_KEY_HEX);
  const event = buildRegistryEvent(rootPrivkey, clientId, registrantHex, [
    normalizedDomain,
  ]);
  // Persist first, then broadcast; roll back on failure
  await saveClaim(env, clientId, registrantHex, [normalizedDomain]);
  try {
    const broadcast = await broadcastEvent(env, event);
    return jsonOk({ ok: true, event: event.id, ...broadcast }, 201);
  } catch (err) {
    await env.REGISTRY_KV.delete(KV_PREFIX_CLAIM + clientId);
    return jsonErr("Failed to broadcast registry event. Please retry: " + err.message, 502);
  }
}

// ── Route: POST /update (two-phase) ──────────────────────────────────────────
/**
 * Phase 1 — issue a challenge nonce:
 *   Body: { clientId, npub }
 *   Response: { ok, nonce, expiresIn, message }
 *
 * Phase 2 — verify and update domains:
 *   Body: { clientId, nonce, signedEvent, domains }
 *   Response: { ok, event, domains, published, total }
 *
 * signedEvent requirements:
 *   - pubkey   === registrant npub (hex)
 *   - content  === the nonce returned by Phase 1
 *   - kind     === 27235  (NIP-98 HTTP Auth)
 *   - created_at within ±5 minutes
 *   - valid Schnorr signature
 */
async function handleUpdate(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonErr("Request body must be valid JSON");
  }

  const { clientId, npub, domains, nonce, signedEvent } = body;

  if (!clientId || typeof clientId !== "string") {
    return jsonErr("clientId is required");
  }

  const existing = await getClaim(env, clientId);
  if (!existing) return jsonErr("clientId not found", 404);

  // ── Phase 1: Issue challenge (no nonce / signedEvent provided) ──────────────
  if (!nonce && !signedEvent) {
    if (!npub) return jsonErr("npub is required to request a challenge");
    const registrantHex = npubToHex(npub);
    if (!registrantHex) return jsonErr("npub is invalid");
    if (existing.registrantHex !== registrantHex) {
      return jsonErr("npub does not own this clientId", 403);
    }

    const nonceBytes = new Uint8Array(32);
    crypto.getRandomValues(nonceBytes);
    const issuedNonce = Array.from(nonceBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    await saveChallenge(env, clientId, issuedNonce, registrantHex);

    return jsonOk({
      ok: true,
      nonce: issuedNonce,
      expiresIn: NONCE_TTL_SEC,
      message:
        "Sign a Nostr event whose content is this nonce, then POST back to /update with nonce and signedEvent.",
    });
  }

  // ── Phase 2: Verify challenge and update domains ─────────────────────────────
  if (!nonce || !signedEvent) {
    return jsonErr(
      "Both nonce and signedEvent are required to complete the update. " +
        "POST without them first to receive a challenge nonce.",
    );
  }
  if (!Array.isArray(domains)) {
    return jsonErr("domains array is required");
  }

  // Validate domains list
  if (domains.length > MAX_DOMAINS) {
    return jsonErr("Too many domains (max " + MAX_DOMAINS + ")");
  }
  const normalizedDomains = [];
  for (const domain of domains) {
    const n = normalizeDomain(domain);
    if (!n)
      return jsonErr("Invalid domain in list: " + String(domain).slice(0, 100));
    normalizedDomains.push(n);
  }
  const uniqueDomains = [...new Set(normalizedDomains)];

  // Fetch and validate challenge
  const challengeRecord = await getChallenge(env, clientId);
  if (!challengeRecord) {
    return jsonErr(
      "No active challenge for this clientId. POST without nonce/signedEvent to request one.",
    );
  }
  if (Date.now() > challengeRecord.expiresAt) {
    await deleteChallenge(env, clientId);
    return jsonErr("Challenge has expired. Request a new one.", 410);
  }
  if (nonce !== challengeRecord.nonce) {
    return jsonErr("nonce does not match the issued challenge");
  }

  // Validate proof event structure
  const { id, pubkey, sig, kind, content, created_at } = signedEvent;
  if (!id || !pubkey || !sig || kind === undefined || content === undefined || !created_at) {
    return jsonErr(
      "signedEvent is missing required NIP-01 fields (id, pubkey, sig, kind, content, created_at)",
    );
  }
  if (pubkey !== existing.registrantHex) {
    return jsonErr("signedEvent pubkey does not match the registered npub");
  }
  if (kind !== 27235) {
    return jsonErr("signedEvent must be kind 27235");
  }
  const ageSec = Math.floor(Date.now() / 1000) - created_at;
  if (ageSec > NONCE_TTL_SEC || ageSec < -30) {
    return jsonErr(
      "signedEvent created_at is outside the acceptable time window (±5 min)",
    );
  }
  if (content !== challengeRecord.nonce) {
    return jsonErr("signedEvent content does not match the issued nonce");
  }

  let signatureValid = false;
  try {
    signatureValid = verifyEvent(signedEvent);
  } catch (_) {
    return jsonErr("signedEvent signature verification threw an error");
  }
  if (!signatureValid) {
    return jsonErr("signedEvent Schnorr signature is invalid");
  }

  // Consume nonce (one-time use)
  await deleteChallenge(env, clientId);

  // Publish updated NIP-33 event
  const rootPrivkey = hexToBytes(env.ROOT_PRIVATE_KEY_HEX);
  const event = buildRegistryEvent(
    rootPrivkey,
    clientId,
    existing.registrantHex,
    uniqueDomains,
  );
  const broadcast = await broadcastEvent(env, event);
  await saveClaim(env, clientId, existing.registrantHex, uniqueDomains);

  return jsonOk({
    ok: true,
    event: event.id,
    domains: uniqueDomains,
    ...broadcast,
  });
}

// ── Main fetch handler ────────────────────────────────────────────────────────

// ── Node.js / local-test compatibility ────────────────────────────────────────
// In-memory KV shim — lets you run and unit-test the worker outside Cloudflare.
class InMemoryKV {
  constructor() { this._store = new Map(); }
  get(key)        { return Promise.resolve(this._store.get(key) ?? null); }
  put(key, value) { this._store.set(key, value); return Promise.resolve(); }
  delete(key)     { this._store.delete(key);     return Promise.resolve(); }
}

export default {
  async fetch(request, env, _ctx) {
    // CORS preflight
    if (request.method === "OPTIONS") return cors204();

    if (request.method !== "POST") {
      return jsonErr("Method not allowed — use POST", 405);
    }

    // Validate that required bindings/secrets are configured
    if (!env.ROOT_PRIVATE_KEY_HEX) {
      return jsonErr(
        "Worker misconfiguration: ROOT_PRIVATE_KEY_HEX secret is not set",
        500,
      );
    }
    if (!env.REGISTRY_KV) {
      return jsonErr(
        "Worker misconfiguration: REGISTRY_KV binding is missing",
        500,
      );
    }
    if (!env.CHALLENGES_KV) {
      return jsonErr(
        "Worker misconfiguration: CHALLENGES_KV binding is missing",
        500,
      );
    }

    const url = new URL(request.url);

    try {
      switch (url.pathname) {
        case "/register":
          return await handleRegister(request, env);
        case "/update":
          return await handleUpdate(request, env);
        default:
          return jsonErr("Not found", 404);
      }
    } catch (err) {
      // Unexpected internal errors — log but don't leak stack traces to clients
      console.error("Registrar unhandled error:", err);
      return jsonErr("Internal server error", 500);
    }
  },
};
