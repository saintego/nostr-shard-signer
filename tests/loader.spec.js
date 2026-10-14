// The npm package's loadNostrBridge(), imported from npm/index.js.
import { test, expect, APP, BUNKER, PUBKEY, blankPage, bridgePage, waitForAuth } from "./fixtures.js";

const load = (page, config) =>
  page.evaluate(async (config) => {
    const { loadNostrBridge } = await import("/npm/index.js");
    const bridge = await loadNostrBridge(config);
    return { same: bridge === window.NostrBridge, apiVersion: bridge.apiVersion };
  }, config);

const bridgeScripts = (page) =>
  page.evaluate(() =>
    [...document.querySelectorAll("script[src]")].map((s) => s.src).filter((s) => s.endsWith("/nostr-bridge.js")),
  );

test.describe("loadNostrBridge", () => {
  test.withExtension();

  test("loads nostr-bridge.js from bunkerOrigin and initializes it", async ({ page, pages }) => {
    pages.set("/", blankPage);
    await page.goto(APP + "/");
    expect(await load(page, { bunkerOrigin: BUNKER + "/" })).toEqual({ same: true, apiVersion: 1 });
    expect(await bridgeScripts(page)).toEqual([BUNKER + "/nostr-bridge.js"]);
    expect(await waitForAuth(page, true)).toEqual({ loggedIn: true, pubkey: PUBKEY });
  });

  test("loads the script once across concurrent calls", async ({ page, pages }) => {
    pages.set("/", blankPage);
    await page.goto(APP + "/");
    await Promise.all([load(page, { bunkerOrigin: BUNKER }), load(page, { bunkerOrigin: BUNKER })]);
    expect(await bridgeScripts(page)).toHaveLength(1);
    await expect(page.locator("#nostr-signer-iframe")).toHaveCount(1);
  });

  test("reuses a bridge the page already loaded with a script tag", async ({ page, pages }) => {
    pages.set("/", bridgePage);
    await page.goto(APP + "/");
    expect(await load(page, { bunkerOrigin: BUNKER })).toEqual({ same: true, apiVersion: 1 });
    expect(await bridgeScripts(page)).toHaveLength(1);
  });

  test("rejects when the script can't be loaded, and a later call retries", async ({ page, pages }) => {
    pages.set("/", blankPage);
    await page.goto(APP + "/");
    await expect(load(page, { bunkerOrigin: "http://offline.test/signer" })).rejects.toThrow(
      /could not load http:\/\/offline\.test\/signer\/nostr-bridge\.js/,
    );
    expect(await bridgeScripts(page)).toEqual([]);
    expect(await load(page, { bunkerOrigin: BUNKER })).toEqual({ same: true, apiVersion: 1 });
  });

  test("rejects a bunkerOrigin that is not a URL", async ({ page, pages }) => {
    pages.set("/", blankPage);
    await page.goto(APP + "/");
    await expect(load(page, { bunkerOrigin: "nope" })).rejects.toThrow(/bunkerOrigin must be an absolute URL/);
  });

  test.describe("with a bridge of another API version", () => {
    test.use({ bridgePatch: { from: "API_VERSION = 1;", to: "API_VERSION = 2;" } });

    test("warns to update the package", async ({ page, pages }) => {
      const warnings = [];
      page.on("console", (m) => m.type() === "warning" && warnings.push(m.text()));
      pages.set("/", blankPage);
      await page.goto(APP + "/");
      expect(await load(page, { bunkerOrigin: BUNKER })).toEqual({ same: true, apiVersion: 2 });
      expect(warnings.join("\n")).toMatch(/API version 2, this package's types describe version 1/);
    });
  });
});
