// The NIP-33 registry key is built into the signer; the embedding page can't
// choose it (#59). Tests run against a build without VITE_ROOT_PUBKEY_HEX.
import { test, expect, APP, BUNKER, bridgePage, collectSignerErrors } from "./fixtures.js";

const ATTACKER_KEY = "b".repeat(64);

// A registrar on the app's own origin that would hand out the page's own key.
function fakeRegistrar(page, pages) {
  pages.set("/r/pubkey", JSON.stringify({ pubkey: ATTACKER_KEY, relays: ["wss://relay.app.test"] }));
  const hits = [];
  page.on("request", (r) => {
    if (r.url().startsWith(APP + "/r/")) hits.push(r.url());
  });
  return hits;
}

test("the removed registrarUrl option warns and isn't passed to the signer", async ({ page, pages }) => {
  const warnings = [];
  page.on("console", (m) => m.type() === "warning" && warnings.push(m.text()));
  pages.set("/", bridgePage);
  await page.goto(APP + "/");
  await page.evaluate(
    (bunkerOrigin) => NostrBridge.init({ bunkerOrigin, clientId: "victim-client", registrarUrl: "http://app.test/r" }),
    BUNKER,
  );
  const src = await page.locator("iframe").first().getAttribute("src");
  expect(new URL(src).searchParams.has("registrarUrl")).toBe(false);
  expect(warnings.some((w) => w.includes("registrarUrl was removed"))).toBe(true);
});

test.describe("an old bridge that still sends registrarUrl", () => {
  test.use({
    bridgePatch: {
      from: 'url.searchParams.set("protocol", String(PROTOCOL_VERSION));',
      to: 'url.searchParams.set("protocol", String(PROTOCOL_VERSION)); url.searchParams.set("registrarUrl", "http://app.test/r");',
    },
  });

  test("the signer ignores it and fails closed without a built-in key", async ({ page, pages }) => {
    const hits = fakeRegistrar(page, pages);
    await collectSignerErrors(page);
    pages.set("/", bridgePage);
    await page.goto(APP + "/");
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin, clientId: "victim-client" }), BUNKER);

    const src = await page.locator("iframe").first().getAttribute("src");
    expect(new URL(src).searchParams.get("registrarUrl")).toBe("http://app.test/r");
    await expect.poll(() => page.evaluate(() => window.signerErrors.map((e) => e.code)), { timeout: 15000 })
      .toContain("MISSING_ROOT_PUBKEY");
    expect(hits).toEqual([]);
  });
});
