// The example pages deployed next to the signer (scripts/assemble-site.sh).
import { test, expect, SIGNER_ORIGIN, BUNKER } from "./fixtures.js";

test("evolustr example ignores a bunker on another origin (#58)", async ({ page }) => {
  const requests = [];
  page.on("request", (r) => requests.push(r.url()));
  await page.goto(BUNKER + "/examples/evolustr.html?bunker=https://example.invalid/x");
  await page.waitForFunction(() => typeof window.NostrBridge === "object");

  expect(requests.filter((u) => new URL(u).hostname === "example.invalid")).toEqual([]);
  expect(requests).toContain(BUNKER + "/nostr-bridge.js");
  expect(await page.evaluate(() => window.TEST_CONFIG.bunkerOrigin)).toBe(BUNKER);
});

test("evolustr example accepts a bunker path on its own origin", async ({ page }) => {
  const requests = [];
  page.on("request", (r) => requests.push(r.url()));
  await page.goto(BUNKER + "/examples/evolustr.html?bunker=" + encodeURIComponent(SIGNER_ORIGIN + "/other/"));
  await page.waitForFunction(() => window.TEST_CONFIG);
  expect(await page.evaluate(() => window.TEST_CONFIG.bunkerOrigin)).toBe(SIGNER_ORIGIN + "/other");
  expect(requests).toContain(SIGNER_ORIGIN + "/other/nostr-bridge.js");
});
