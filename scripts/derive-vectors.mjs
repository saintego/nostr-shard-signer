#!/usr/bin/env node
// Generates the v1 derivation test vectors (#73, D2; check C12) with Node's own
// HKDF, independent of the WebCrypto code in bunker/src/lib/derive.ts.
//
//   node scripts/derive-vectors.mjs > bunker/src/lib/derive.vectors.json
//
// The vectors are frozen at launch: regenerate only while v1 is a draft.

import { hkdfSync } from "node:crypto";
import { getPublicKey } from "nostr-tools/pure";

const P = "nostr-shard-signer/v1/";
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const hex = (b) => Buffer.from(b).toString("hex");
const hkdf = (ikm, label) => new Uint8Array(hkdfSync("sha256", ikm, new Uint8Array(0), Buffer.from(label, "utf8"), 32));
const secret = (ikm, label) => {
  for (let l = label; ; l += "/retry") {
    const k = hkdf(ikm, l);
    const n = BigInt("0x" + hex(k));
    if (n > 0n && n < N) return k;
  }
};
const withPub = (k) => ({ secret: hex(k), pubkey: getPublicKey(k) });

// Inputs and their canonical forms (WHATWG URL origin; see canonicalOrigin).
const ORIGINS = [
  ["https://example.com", "https://example.com"],
  ["HTTPS://Example.COM:443/some/path?q=1#x", "https://example.com"],
  ["https://example.com:8443", "https://example.com:8443"],
  ["http://localhost:8080/", "http://localhost:8080"],
  ["https://bücher.example", "https://xn--bcher-kva.example"],
  ["https://saintego.github.io/nostr-shard-signer/", "https://saintego.github.io"],
];

const LOGIN_KEYS = [
  "0101010101010101010101010101010101010101010101010101010101010101",
  "f3a1c5d2e4b6978899aabbccddeeff00112233445566778899aabbccddeeff01",
];

// A site's own login key (a site with its own clientId), for the marker address (D7).
const SITE_LOGIN_KEY = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

const vectors = LOGIN_KEYS.map((loginHex) => {
  const login = Buffer.from(loginHex, "hex");
  const root = secret(login, P + "root");
  return {
    globalLoginKey: loginHex,
    root: withPub(root),
    identities: [0, 1, 2, 1000].map((i) => ({ index: i, ...withPub(secret(root, P + "identity/" + i)) })),
    sites: ORIGINS.map(([input, canonical]) => ({
      input,
      canonical,
      markerKey: withPub(secret(root, P + "site-marker/" + canonical)),
      storeKey: hex(hkdf(root, P + "site-store/" + canonical)),
      markerAddress: { siteLoginKey: SITE_LOGIN_KEY, d: hex(hkdf(Buffer.from(SITE_LOGIN_KEY, "hex"), P + "marker-address/" + canonical)) },
    })),
    globalStoreKey: hex(hkdf(root, P + "global-store")),
    counterKey: withPub(secret(root, P + "counter")),
    configKey: withPub(secret(root, P + "config")),
    backupKey: hex(hkdf(root, P + "backup")),
    // D20: from the Evolustr master secret M; the login key stands in for M here.
    settingsKeyFromM: { m: loginHex, key: hex(hkdf(login, P + "settings")) },
  };
});

console.log(JSON.stringify({ version: "v1-draft", hkdf: "HKDF-SHA256, empty salt, info = label, 32 bytes", vectors }, null, 2));
