#!/usr/bin/env node
// The outside monitor for the shared Web3Auth projects (#73 D21, #91). Reads a
// project's public configuration (what Web3Auth's SDK reads, C15) and fails if
// it isn't what scripts/sharedProjectExpected.json says: a site added to or
// removed from the allowlist, or key export turned off. A site added there
// could run the shared sign-in itself and obtain users' keys; the signer's own
// canary (bunker/src/lib/canary.ts) pauses new sign-ins, and this alerts the
// operator (the scheduled workflow's failed run).
//
//   node scripts/checkSharedProject.mjs production   # SHARED_CLIENT_ID from bunker/src/lib/shared.ts
//   CLIENT_ID=BDI… node scripts/checkSharedProject.mjs preview
//
// Exit codes: 0 as expected (or no client ID: nothing to check), 1 changed,
// 2 unreadable.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const which = process.argv[2] ?? "production";
const expected = JSON.parse(readFileSync(path.join(root, "scripts/sharedProjectExpected.json"), "utf8"))[which];
if (!expected) {
  console.error(`No "${which}" entry in scripts/sharedProjectExpected.json`);
  process.exit(2);
}

/** The production client ID, as the signer is built with it. */
function sourceClientId() {
  const src = readFileSync(path.join(root, "bunker/src/lib/shared.ts"), "utf8");
  return src.match(/export const SHARED_CLIENT_ID = '([^']*)'/)?.[1] ?? "";
}

const clientId = process.env.CLIENT_ID || (which === "production" ? sourceClientId() : "");
if (!clientId) {
  console.log(`No client ID for "${which}": nothing to check.`);
  process.exit(0);
}

const norm = (u) => String(u).trim().replace(/\/+$/, "");
const url = `https://api.web3auth.io/signer-service/api/v2/configuration?project_id=${encodeURIComponent(
  clientId,
)}&network=${encodeURIComponent(expected.network)}`;

let config;
try {
  const res = await fetch(url, { signal: AbortSignal.timeout(20000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  config = await res.json();
} catch (e) {
  console.error(`The ${which} project's configuration could not be read: ${e.message}`);
  process.exit(2);
}

const urls = config?.whitelist?.urls;
if (!Array.isArray(urls) || typeof config?.enableKeyExport !== "boolean") {
  console.error(`The ${which} project's configuration has an unknown shape:`, JSON.stringify(config));
  process.exit(2);
}

const want = new Set(expected.urls.map(norm));
const have = new Set(urls.map(norm));
const added = [...have].filter((u) => !want.has(u));
const removed = [...want].filter((u) => !have.has(u));
// The sign-in connections (#145): with Web3Auth's panel (#113) every enabled
// one is offered, and a changed one gives users other keys. Frozen once the
// expected file lists them; until then printed, to copy there.
const connectionsNow = (Array.isArray(config.embeddedWalletAuth) ? config.embeddedWalletAuth : [])
  .map((c) => `${c.authConnection}:${c.groupedAuthConnectionId ?? c.authConnectionId}:${c.clientId}`)
  .sort();
const connectionProblems = [];
if (Array.isArray(expected.connections)) {
  const want = new Set(expected.connections);
  const have = new Set(connectionsNow);
  for (const c of have) if (!want.has(c)) connectionProblems.push(`connection added or changed: ${c}`);
  for (const c of want) if (!have.has(c)) connectionProblems.push(`connection removed or changed: ${c}`);
} else {
  console.log(`No "connections" in the expected list for "${which}"; to freeze them, add:\n${JSON.stringify(connectionsNow, null, 2)}`);
}
const problems = [
  ...added.map((u) => `added to the allowlist (it could obtain users' keys): ${u}`),
  ...removed.map((u) => `missing from the allowlist (sign-in fails there): ${u}`),
  ...(config.enableKeyExport ? [] : ["key export is off (the signer can't get keys)"]),
  ...connectionProblems,
];
if (problems.length) {
  console.error(`The ${which} shared project changed:\n- ${problems.join("\n- ")}`);
  console.error("If intended, update scripts/sharedProjectExpected.json; if not, fix the project in Web3Auth's dashboard now.");
  process.exit(1);
}
console.log(`The ${which} shared project is as expected (${have.size} sites, key export on).`);
