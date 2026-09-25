/**
 * registrar-worker.js
 *
 * Cloudflare Worker — NIP-33 Root Pubkey Registry
 *
 * Securely binds Web3Auth clientIds to authorized domains and publishes
 * the binding as a NIP-33 (kind:30078) event signed by the server's root keypair.
 *
 * Required Cloudflare bindings (set via wrangler.toml + `wrangler secret put`):
 *   ROOT_PRIVATE_KEY_HEX  — root private key: 64-char hex OR bech32 nsec (secret, never in code)
 *   REGISTRY_KV           — KV namespace for clientId → domain claims
 *   CHALLENGES_KV         — KV namespace for one-time ownership challenges
 *   RELAY_URLS            — comma-separated relay WebSocket URLs (env var)
 *
 * Endpoints:
 *   GET  /pubkey    — return root pubkey hex + configured relay URLs (public, no auth)
 *   GET  /health    — report of the last registry sync (public, no auth)
 *   POST /register   — claim a new clientId → domain binding
 *   POST /update     — two-phase: (1) issue challenge nonce, (2) verify and update domains
 *   POST /sync       — run the registry sync now (at most once per SYNC_COOLDOWN_SEC)
 *
 * Registry sync (daily cron, see wrangler.toml, or POST /sync):
 *   Relays don't sync with each other and may lose data, so every published
 *   registry event is also kept in REGISTRY_KV (event:{clientId}). The sync
 *   reads all relays, keeps the newest event per clientId, backfills KV, and
 *   re-sends the stored signed event to every relay that lacks it.
 *
 * Security model:
 *   - /register is open: anyone can claim an unclaimed clientId.
 *     If a clientId is already claimed by a *different* pubkey, the request is rejected.
 *   - /update requires a cryptographic ownership proof (signed nonce, NIP-98 style).
 *   - Nonces are one-time-use and expire after 5 minutes.
 *   - All domain inputs are normalised to their HTTPS origin to prevent bypass via path tricks.
 */

import { finalizeEvent, verifyEvent, nip19, getPublicKey } from "nostr-tools";

// ── Constants ─────────────────────────────────────────────────────────────────

const KV_PREFIX_CLAIM = "claim:"; // claim:{clientId}  → JSON  (in REGISTRY_KV)
const KV_PREFIX_NONCE = "nonce:"; // nonce:{clientId}  → JSON  (in CHALLENGES_KV, TTL-bound)
const KV_PREFIX_EVENT = "event:"; // event:{clientId}  → signed registry event (in REGISTRY_KV)
const KV_HEALTH = "health:last"; // report of the last sync (in REGISTRY_KV)
const SYNC_COOLDOWN_SEC = 300; // minimum gap between POST /sync runs
// A registration on fewer relays than this (or on fewer than all of them, when
// fewer relays are configured) makes /health report "degraded".
const MIN_HEALTHY_COPIES = 3;
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

/**
 * Decode ROOT_PRIVATE_KEY_HEX to a 32-byte Uint8Array.
 * Accepts either a 64-char lowercase hex string or a bech32 nsec.
 */
function getRootPrivkeyBytes(env) {
  const raw = env.ROOT_PRIVATE_KEY_HEX;
  if (!raw) throw new Error("ROOT_PRIVATE_KEY_HEX is not set");
  if (typeof raw === "string" && raw.startsWith("nsec1")) {
    const decoded = nip19.decode(raw);
    if (decoded.type !== "nsec")
      throw new Error("ROOT_PRIVATE_KEY_HEX: expected nsec");
    return decoded.data; // already Uint8Array
  }
  return hexToBytes(raw.toLowerCase().trim());
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
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
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

function getRelayUrls(env) {
  return (env.RELAY_URLS || "wss://relay.damus.io")
    .split(",")
    .map((u) => u.trim())
    .filter(Boolean);
}

/**
 * Broadcast to all configured relays and wait for every one to answer (or time
 * out): returning on the first OK would let the runtime cancel the other
 * sockets once the response is sent, leaving the event on a single relay.
 * Throws, naming each relay's failure, if no relay accepted the event.
 */
async function broadcastEvent(env, event) {
  const relayUrls = getRelayUrls(env);

  const results = await Promise.allSettled(
    relayUrls.map((url) => publishToRelay(url, event)),
  );
  const published = results.filter((r) => r.status === "fulfilled").length;
  if (published === 0) {
    throw new Error(
      results
        .map((r, i) => relayUrls[i] + ": " + (r.reason?.message || r.reason))
        .join("; "),
    );
  }
  return { published, total: relayUrls.length };
}

// ── Registry sync ─────────────────────────────────────────────────────────────

/** Fetch all events matching filter from one relay (until EOSE or timeout). */
function queryRelay(relayUrl, filter) {
  return new Promise((resolve, reject) => {
    const events = [];
    let ws;
    const timer = setTimeout(() => {
      try {
        ws.close();
      } catch (_) {}
      reject(new Error("Timeout"));
    }, 10_000);
    try {
      ws = new WebSocket(relayUrl);
    } catch (err) {
      clearTimeout(timer);
      reject(err);
      return;
    }
    ws.addEventListener("open", () =>
      ws.send(JSON.stringify(["REQ", "sync", filter])),
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
      if (!Array.isArray(msg) || msg[1] !== "sync") return;
      if (msg[0] === "EVENT") events.push(msg[2]);
      else if (msg[0] === "EOSE" || msg[0] === "CLOSED") {
        clearTimeout(timer);
        ws.close();
        msg[0] === "EOSE"
          ? resolve(events)
          : reject(new Error(msg[2] || "Relay closed the subscription"));
      }
    });
  });
}

/**
 * Send several events over one connection. Resolves with the ids the relay
 * accepted once every event is answered, or on timeout with those so far.
 */
function publishEventsToRelay(relayUrl, events) {
  return new Promise((resolve) => {
    const accepted = new Set();
    let answered = 0;
    let ws;
    const finish = () => {
      clearTimeout(timer);
      try {
        ws.close();
      } catch (_) {}
      resolve(accepted);
    };
    const timer = setTimeout(finish, 15_000);
    try {
      ws = new WebSocket(relayUrl);
    } catch (_) {
      finish();
      return;
    }
    ws.addEventListener("open", () => {
      for (const ev of events) ws.send(JSON.stringify(["EVENT", ev]));
    });
    ws.addEventListener("error", finish);
    ws.addEventListener("message", (e) => {
      let msg;
      try {
        msg = JSON.parse(e.data);
      } catch {
        return;
      }
      if (!Array.isArray(msg) || msg[0] !== "OK") return;
      if (msg[2] !== false) accepted.add(msg[1]);
      if (++answered >= events.length) finish();
    });
  });
}

function dTag(event) {
  return event.tags?.find((t) => t[0] === "d")?.[1];
}

/**
 * Make every configured relay and KV hold the newest registry event of every
 * clientId. Stores and returns a health report.
 */
async function syncRegistry(env) {
  const rootHex = getPublicKey(getRootPrivkeyBytes(env));
  const relayUrls = getRelayUrls(env);

  const stored = await loadStoredEvents(env);
  const reads = await Promise.allSettled(
    relayUrls.map((url) =>
      queryRelay(url, { kinds: [30078], authors: [rootHex] }),
    ),
  );

  // Newest valid event per clientId across KV and all relays. Relay data is
  // untrusted: only events with a valid root signature count.
  const newest = new Map();
  const consider = (ev) => {
    const d = ev && dTag(ev);
    if (!d || ev.kind !== 30078 || ev.pubkey !== rootHex) return;
    const cur = newest.get(d);
    if (cur && (cur.id === ev.id || cur.created_at >= ev.created_at)) return;
    if (!verifyEvent(ev)) return;
    newest.set(d, ev);
  };
  for (const ev of stored.values()) consider(ev);
  for (const r of reads) if (r.status === "fulfilled") r.value.forEach(consider);

  // Backfill KV (events published before KV storage existed, or updated
  // elsewhere).
  let kvBackfilled = 0;
  for (const [d, ev] of newest) {
    if (stored.get(d)?.id !== ev.id) {
      await saveEvent(env, d, ev);
      kvBackfilled++;
    }
  }

  // Re-send to each reachable relay whatever it lacks. Unreachable relays are
  // left for the next run.
  const copies = new Map([...newest.keys()].map((d) => [d, 0]));
  const relays = await Promise.all(
    relayUrls.map(async (url, i) => {
      if (reads[i].status === "rejected") {
        return { url, reachable: false, error: reads[i].reason?.message || String(reads[i].reason) };
      }
      const held = new Set(reads[i].value.map((ev) => ev.id));
      const missing = [...newest.values()].filter((ev) => !held.has(ev.id));
      const accepted = missing.length
        ? await publishEventsToRelay(url, missing)
        : new Set();
      for (const [d, ev] of newest) {
        if (held.has(ev.id) || accepted.has(ev.id)) copies.set(d, copies.get(d) + 1);
      }
      return {
        url,
        reachable: true,
        missing: missing.length,
        repaired: accepted.size,
      };
    }),
  );

  const wanted = Math.min(MIN_HEALTHY_COPIES, relayUrls.length);
  const underReplicated = [...copies]
    .filter(([, n]) => n < wanted)
    .map(([clientId, n]) => ({ clientId, copies: n }));
  const reachable = relays.filter((r) => r.reachable).length;
  const report = {
    status:
      underReplicated.length === 0 && reachable * 2 >= relayUrls.length
        ? "ok"
        : "degraded",
    checkedAt: new Date().toISOString(),
    registrations: newest.size,
    kvBackfilled,
    relaysReachable: reachable + "/" + relayUrls.length,
    relays,
    underReplicated,
  };
  await env.REGISTRY_KV.put(KV_HEALTH, JSON.stringify(report));
  if (report.status !== "ok") {
    console.warn("Registry sync degraded:", JSON.stringify(report));
  }
  return report;
}

async function handleHealth(env) {
  const raw = await env.REGISTRY_KV.get(KV_HEALTH);
  return jsonOk(
    raw ? JSON.parse(raw) : { status: "unknown", message: "No sync has run yet. POST /sync to run one." },
  );
}

async function handleSync(env) {
  const raw = await env.REGISTRY_KV.get(KV_HEALTH);
  const last = raw ? JSON.parse(raw) : null;
  const ageSec = last ? (Date.now() - Date.parse(last.checkedAt)) / 1000 : Infinity;
  if (ageSec < SYNC_COOLDOWN_SEC) {
    return jsonErr(
      "Sync ran " + Math.round(ageSec) + "s ago; try again in " +
        Math.ceil(SYNC_COOLDOWN_SEC - ageSec) + "s. GET /health shows its report.",
      429,
    );
  }
  return jsonOk(await syncRegistry(env));
}

// ── KV helpers (two separate namespaces) ─────────────────────────────────────

async function getClaim(env, clientId) {
  const raw = await env.REGISTRY_KV.get(KV_PREFIX_CLAIM + clientId);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function saveClaim(env, clientId, registrantHex, domains) {
  await env.REGISTRY_KV.put(
    KV_PREFIX_CLAIM + clientId,
    JSON.stringify({ registrantHex, domains }),
  );
}

async function saveEvent(env, clientId, event) {
  await env.REGISTRY_KV.put(KV_PREFIX_EVENT + clientId, JSON.stringify(event));
}

/** All stored registry events, keyed by clientId. */
async function loadStoredEvents(env) {
  const events = new Map();
  let cursor;
  do {
    const page = await env.REGISTRY_KV.list({ prefix: KV_PREFIX_EVENT, cursor });
    for (const { name } of page.keys) {
      const raw = await env.REGISTRY_KV.get(name);
      try {
        if (raw) events.set(name.slice(KV_PREFIX_EVENT.length), JSON.parse(raw));
      } catch (_) {}
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return events;
}

async function saveChallenge(env, clientId, nonce, registrantHex) {
  await env.CHALLENGES_KV.put(
    KV_PREFIX_NONCE + clientId,
    JSON.stringify({
      nonce,
      registrantHex,
      expiresAt: Date.now() + NONCE_TTL_SEC * 1000,
    }),
    { expirationTtl: NONCE_TTL_SEC },
  );
}

async function getChallenge(env, clientId) {
  const raw = await env.CHALLENGES_KV.get(KV_PREFIX_NONCE + clientId);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
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
    const rootPrivkey = getRootPrivkeyBytes(env);
    const event = buildRegistryEvent(
      rootPrivkey,
      clientId,
      registrantHex,
      existing.domains,
    );
    await saveClaim(env, clientId, registrantHex, existing.domains);
    try {
      const broadcast = await broadcastEvent(env, event);
      await saveEvent(env, clientId, event);
      return jsonOk({ ok: true, event: event.id, ...broadcast });
    } catch (err) {
      // Roll back the domain addition on broadcast failure
      existing.domains.pop();
      await saveClaim(env, clientId, registrantHex, existing.domains);
      return jsonErr(
        "Failed to broadcast registry event. Please retry: " + err.message,
        502,
      );
    }
  }

  // ── New claim ───────────────────────────────────────────────────────────────
  const rootPrivkey = getRootPrivkeyBytes(env);
  const event = buildRegistryEvent(rootPrivkey, clientId, registrantHex, [
    normalizedDomain,
  ]);
  // Persist first, then broadcast; roll back on failure
  await saveClaim(env, clientId, registrantHex, [normalizedDomain]);
  try {
    const broadcast = await broadcastEvent(env, event);
    await saveEvent(env, clientId, event);
    return jsonOk({ ok: true, event: event.id, ...broadcast }, 201);
  } catch (err) {
    await env.REGISTRY_KV.delete(KV_PREFIX_CLAIM + clientId);
    return jsonErr(
      "Failed to broadcast registry event. Please retry: " + err.message,
      502,
    );
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
  if (
    !id ||
    !pubkey ||
    !sig ||
    kind === undefined ||
    content === undefined ||
    !created_at
  ) {
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
  const rootPrivkey = getRootPrivkeyBytes(env);
  const event = buildRegistryEvent(
    rootPrivkey,
    clientId,
    existing.registrantHex,
    uniqueDomains,
  );
  const broadcast = await broadcastEvent(env, event);
  await saveClaim(env, clientId, existing.registrantHex, uniqueDomains);
  await saveEvent(env, clientId, event);

  return jsonOk({
    ok: true,
    event: event.id,
    domains: uniqueDomains,
    ...broadcast,
  });
}

// ── GET /pubkey ──────────────────────────────────────────────────────────────

/**
 * Return the root pubkey (derived from ROOT_PRIVATE_KEY_HEX) and the configured
 * relay URLs so clients can query Nostr directly without hardcoding anything.
 */
function handlePubkey(env) {
  const pubkey = getPublicKey(getRootPrivkeyBytes(env));
  const relays = getRelayUrls(env);
  return new Response(JSON.stringify({ pubkey, relays }), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

// ── Main fetch handler ────────────────────────────────────────────────────────

// ── Node.js / local-test compatibility ────────────────────────────────────────
// In-memory KV shim — lets you run and unit-test the worker outside Cloudflare.
class InMemoryKV {
  constructor() {
    this._store = new Map();
  }
  get(key) {
    return Promise.resolve(this._store.get(key) ?? null);
  }
  put(key, value) {
    this._store.set(key, value);
    return Promise.resolve();
  }
  delete(key) {
    this._store.delete(key);
    return Promise.resolve();
  }
  list({ prefix = "" } = {}) {
    const keys = [...this._store.keys()]
      .filter((name) => name.startsWith(prefix))
      .map((name) => ({ name }));
    return Promise.resolve({ keys, list_complete: true });
  }
}

export default {
  async fetch(request, env, _ctx) {
    // CORS preflight
    if (request.method === "OPTIONS") return cors204();

    const url = new URL(request.url);

    // GET /pubkey is the only public read endpoint — no auth required
    if (request.method === "GET" && url.pathname === "/pubkey") {
      if (!env.ROOT_PRIVATE_KEY_HEX) {
        return jsonErr(
          "Worker misconfiguration: ROOT_PRIVATE_KEY_HEX secret is not set",
          500,
        );
      }
      return handlePubkey(env);
    }

    if (request.method === "GET" && url.pathname === "/health") {
      if (!env.REGISTRY_KV) {
        return jsonErr("Worker misconfiguration: REGISTRY_KV binding is missing", 500);
      }
      return handleHealth(env);
    }

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

    try {
      switch (url.pathname) {
        case "/register":
          return await handleRegister(request, env);
        case "/update":
          return await handleUpdate(request, env);
        case "/sync":
          return await handleSync(env);
        default:
          return jsonErr("Not found", 404);
      }
    } catch (err) {
      // Unexpected internal errors — log but don't leak stack traces to clients
      console.error("Registrar unhandled error:", err);
      return jsonErr("Internal server error", 500);
    }
  },

  // Daily registry sync; schedule in wrangler.toml [triggers].
  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(syncRegistry(env));
  },
};
