import { test as base, expect } from "@playwright/test";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "bunker/dist");

// Two origins served from the repo, laid out like the GitHub Pages site:
// the signer (with nostr-bridge.js next to it) and the app embedding it.
export const SIGNER_ORIGIN = "http://signer.test";
export const BUNKER = SIGNER_ORIGIN + "/nostr-shard-signer";
export const APP = "http://app.test";
export const PUBKEY = "a".repeat(64);

if (!existsSync(path.join(dist, "index.html")))
  throw new Error("bunker/dist is missing: run `npm run build` first (npm test does it)");

// A NIP-07 extension, installed in the app page only (not the signer iframe).
function fakeExtension(pubkey) {
  if (location.origin !== "http://app.test") return;
  window.extensionCalls = [];
  window.nostr = {
    async getPublicKey() {
      window.extensionCalls.push("getPublicKey");
      return pubkey;
    },
    async signEvent(event) {
      window.extensionCalls.push("signEvent");
      return { ...event, pubkey, id: "1".repeat(64), sig: "2".repeat(128) };
    },
  };
}

export const test = base.extend({
  // Pages for the app origin: tests register them with pages.set(path, html).
  pages: async ({}, use) => use(new Map()),
  // Optional { from, to } text replacement in nostr-bridge.js, to simulate
  // another bridge version.
  bridgePatch: [null, { option: true }],

  context: async ({ context, pages, bridgePatch }, use) => {
    await context.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (url.origin === SIGNER_ORIGIN) {
        const p = url.pathname.replace(/^\/nostr-shard-signer/, "");
        if (p === "/signer.html") return route.fulfill({ path: path.join(dist, "index.html") });
        if (p.startsWith("/assets/")) return route.fulfill({ path: path.join(dist, p) });
        if (p === "/nostr-bridge.js") {
          const src = await readFile(path.join(root, "nostr-bridge.js"), "utf8");
          return route.fulfill({
            contentType: "text/javascript",
            body: bridgePatch ? src.replace(bridgePatch.from, bridgePatch.to) : src,
          });
        }
      }
      if (url.origin === APP) {
        if (pages.has(url.pathname))
          return route.fulfill({ contentType: "text/html", body: pages.get(url.pathname) });
        if (url.pathname.startsWith("/npm/"))
          return route.fulfill({ path: path.join(root, url.pathname) });
      }
      // Everything else (window.nostr.js CDN, avatars, …) is offline.
      return route.abort();
    });
    // Relays: refuse connections.
    await context.routeWebSocket(/.*/, (ws) => ws.close());
    await use(context);
  },
});

// The app page with the extension installed, loading nostr-bridge.js from the signer.
test.withExtension = () =>
  test.beforeEach(async ({ context }) => {
    await context.addInitScript(fakeExtension, PUBKEY);
  });

export const bridgePage = `<!doctype html><html><head>
<script src="${BUNKER}/nostr-bridge.js"></script>
</head><body></body></html>`;

export const blankPage = `<!doctype html><html><head></head><body></body></html>`;

// Resolves with the first auth state matching loggedIn.
export function waitForAuth(page, loggedIn) {
  return page.evaluate(
    (loggedIn) =>
      new Promise((resolve) => {
        const off = NostrBridge.onAuthChange((s) => {
          if (s.loggedIn !== loggedIn) return;
          queueMicrotask(() => off());
          resolve(s);
        });
      }),
    loggedIn,
  );
}

// Collects the bridge's SIGNER_ERROR events (origin "") into window.signerErrors.
export function collectSignerErrors(page) {
  return page.addInitScript(() => {
    window.signerErrors = [];
    window.addEventListener("message", (e) => {
      if (e.origin === "" && e.data?.type === "SIGNER_ERROR") window.signerErrors.push(e.data);
    });
  });
}

export { expect };
