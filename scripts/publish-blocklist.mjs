#!/usr/bin/env node
// Publishes the shared sign-in block list (#65): origins that get no
// Google/Apple/X through the hosted signer's shared project. Signed with the
// registry root key, so the signer trusts it; each publish replaces the whole
// list. See README → Deployment → "Blocking a site from shared sign-in".
//
//   ROOT_PRIVATE_KEY_HEX=<hex or nsec> node scripts/publish-blocklist.mjs https://evil.example '*.bad.example'
//   ROOT_PRIVATE_KEY_HEX=… node scripts/publish-blocklist.mjs --clear       # unblock every site
//
// Options: --dry-run (print the signed event, publish nothing),
// --relays wss://a,wss://b (default: REGISTRY_RELAYS, else the signer's
// DEFAULT_REGISTRY_RELAYS).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import { decode } from "nostr-tools/nip19";
import { SimplePool } from "nostr-tools/pool";

// Must match BLOCKLIST_D_TAG in bunker/src/lib/blocklist.ts. It contains ":",
// which the registrar never accepts in a clientId.
const D_TAG = "nostr-shard-signer:shared-blocked";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function fail(message) {
  console.error("publish-blocklist: " + message);
  process.exit(1);
}

function rootKey() {
  const raw = (process.env.ROOT_PRIVATE_KEY_HEX ?? "").trim();
  if (!raw) fail("set ROOT_PRIVATE_KEY_HEX (64-char hex or nsec) in the environment");
  if (raw.startsWith("nsec1")) {
    const decoded = decode(raw);
    if (decoded.type !== "nsec") fail("ROOT_PRIVATE_KEY_HEX: expected an nsec");
    return decoded.data;
  }
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) fail("ROOT_PRIVATE_KEY_HEX: expected 64 hex characters");
  return Uint8Array.from(raw.match(/../g), (h) => parseInt(h, 16));
}

function defaultRelays() {
  const fromEnv = (process.env.REGISTRY_RELAYS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (fromEnv.length) return fromEnv;
  const src = readFileSync(path.join(root, "bunker/src/lib/nostr.ts"), "utf8");
  const block = src.match(/DEFAULT_REGISTRY_RELAYS\s*=\s*\[([\s\S]*?)\]/);
  return block ? [...block[1].matchAll(/"(wss:\/\/[^"]+)"/g)].map((m) => m[1]) : [];
}

/** "https://evil.example" (any origin) or "*.example.com"; lowercase. */
function normalizeEntry(entry) {
  const e = entry.trim().toLowerCase();
  if (/^\*\.[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(e)) return e;
  try {
    const url = new URL(e);
    if (url.protocol === "https:" || url.protocol === "http:") return url.origin;
  } catch (_) {}
  fail(`not an origin or "*.host": ${entry}`);
}

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const clear = args.includes("--clear");
const relaysArg = args.find((a) => a.startsWith("--relays"));
let relays = defaultRelays();
const rest = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--dry-run" || a === "--clear") continue;
  if (a.startsWith("--relays")) {
    const value = a.includes("=") ? a.split("=")[1] : args[++i];
    relays = (value ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    continue;
  }
  if (a.startsWith("--")) fail(`unknown option ${a}`);
  rest.push(a);
}
if (relaysArg && relays.length === 0) fail("--relays needs a comma-separated list");
if (!clear && rest.length === 0) fail("name the origins to block, or pass --clear to unblock every site");
if (clear && rest.length > 0) fail("--clear takes no origins");
if (relays.length === 0) fail("no relays: set REGISTRY_RELAYS or pass --relays");

const origins = [...new Set(rest.map(normalizeEntry))];
const key = rootKey();
const event = finalizeEvent(
  {
    kind: 30078,
    created_at: Math.floor(Date.now() / 1000),
    tags: [["d", D_TAG]],
    content: JSON.stringify({ origins }),
  },
  key,
);

console.log(`Root key ${getPublicKey(key)}`);
console.log(origins.length ? `Blocking: ${origins.join(", ")}` : "Blocking no site (list cleared)");
if (dryRun) {
  console.log(JSON.stringify(event, null, 2));
  process.exit(0);
}

const pool = new SimplePool();
const results = await Promise.allSettled(pool.publish(relays, event));
pool.close(relays);
let accepted = 0;
results.forEach((r, i) => {
  if (r.status === "fulfilled") accepted++;
  console.log(`${r.status === "fulfilled" ? "ok  " : "fail"} ${relays[i]}${r.status === "rejected" ? `: ${r.reason?.message ?? r.reason}` : ""}`);
});
if (accepted === 0) fail("no relay accepted the event");
console.log(`Published to ${accepted} of ${relays.length} relays. Signers read it on their next start.`);
process.exit(0);
