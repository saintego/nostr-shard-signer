// The v1 check kit (#73) on two made-up https origins, so the cross-site
// checks run as they would between GitHub Pages and the Cloudflare preview.
import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../bunker/dist");
const A = "https://a.test";
const B = "https://b.test";
const page = (origin, q) => `${origin}/nostr-shard-signer/checks.html?other=${q ?? B}&${"c="}`;

test.beforeEach(async ({ context }) => {
  await context.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== A && url.origin !== B) return route.abort();
    const p = url.pathname.replace(/^\/nostr-shard-signer/, "");
    if (p === "/checks.html") {
      // Allow the test origins as frames (the deployed page lists the real ones).
      const html = (await readFile(path.join(dist, "checks.html"), "utf8")).replace("frame-src ", `frame-src ${A} ${B} `);
      return route.fulfill({ contentType: "text/html", body: html });
    }
    if (p.startsWith("/assets/")) return route.fulfill({ path: path.join(dist, p) });
    return route.abort();
  });
  await context.routeWebSocket(/.*/, (ws) => ws.close());
});

test("C12: derivation vectors match in the browser", async ({ page: p }) => {
  await p.goto(page(A) + "C12");
  await expect(p.locator(".log .pass")).toContainText("All derivation vectors match");
  await expect(p.locator(".log .fail")).toHaveCount(0);
});

test("C19: the tab handshakes with the cross-site iframe and drops the store when it goes", async ({ page: p, context }) => {
  await p.goto(page(A) + "C19");
  const frame = p.frameLocator("iframe");
  const [tab] = await Promise.all([
    context.waitForEvent("page"),
    frame.getByRole("button", { name: "Open the signer tab" }).click(),
  ]);
  await expect(tab.locator(".log")).toContainText("Handshake done");
  await expect(tab.locator(".log")).toContainText("No Cross-Origin-Opener-Policy");
  await expect(tab.locator("h2")).toContainText(`Connected to the widget on ${A}`);
  await p.getByRole("button", { name: "Remove the iframe" }).click();
  await expect(tab.locator("h2")).toHaveText("Store dropped");
});

test("C8: storage checks run at top level and in the cross-site iframe", async ({ page: p }) => {
  await p.goto(page(A) + "C8");
  await expect(p.locator(".log").first()).toContainText("OPFS sync access handle in a worker: ok");
  const frame = p.frameLocator("iframe");
  await expect(frame.locator(".log")).toContainText("OPFS sync access handle in a worker");
  await expect(frame.locator(".log")).toContainText("non-extractable key stored");
});
