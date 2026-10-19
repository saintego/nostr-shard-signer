// nostr-bridge.js and signer.html together, without a clientId: sign-in goes
// through a NIP-07 extension, but every auth change still round-trips through
// the signer iframe.
import {
  test, expect, APP, BUNKER, PUBKEY,
  bridgePage, waitForAuth, collectSignerErrors,
} from "./fixtures.js";

test.describe("with a NIP-07 extension", () => {
  test.withExtension();

  test.beforeEach(async ({ page, pages }) => {
    pages.set("/", bridgePage);
    await page.goto(APP + "/");
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
  });

  test("signs in with the extension and routes signing to it", async ({ page }) => {
    expect(await waitForAuth(page, true)).toEqual({ loggedIn: true, pubkey: PUBKEY });
    expect(await page.evaluate(() => window.nostr.getPublicKey())).toBe(PUBKEY);

    const signed = await page.evaluate(() =>
      window.nostr.signEvent({ kind: 1, created_at: 1, tags: [], content: "hi" }),
    );
    expect(signed).toMatchObject({ kind: 1, content: "hi", pubkey: PUBKEY });
    expect(await page.evaluate(() => window.extensionCalls)).toContain("signEvent");
    expect(await page.evaluate(() => NostrBridge.getSavedSession())).toEqual({ pubkey: PUBKEY, mode: "wnj" });
  });

  test("injects the signer iframe with the protocol version and gets its hello", async ({ page }) => {
    const iframe = page.locator("#nostr-signer-iframe");
    const src = new URL(await iframe.getAttribute("src"));
    expect(src.origin + src.pathname).toBe(BUNKER + "/signer.html");
    expect(src.searchParams.get("protocol")).toBe("1");
    expect(src.searchParams.get("nostrSigner")).toBe("extension");
    expect(src.searchParams.get("parentOrigin")).toBe(APP);
    expect(src.searchParams.get("poweredBy")).toBeNull();
    // The key backup file is downloaded from inside the iframe.
    expect(await iframe.getAttribute("sandbox")).toContain("allow-downloads");

    // The signer shows the extension user's profile once the bridge sends WNJ_SESSION.
    await expect(page.locator("#nostr-signer-container")).toHaveCSS("width", "48px");
  });

  test("logout() and login() round-trip through the signer iframe", async ({ page }) => {
    await waitForAuth(page, true);
    // Wait for the iframe to show the avatar (it has the session).
    await expect(page.locator("#nostr-signer-container")).toHaveCSS("width", "48px");

    await page.evaluate(() => NostrBridge.logout());
    expect(await page.evaluate(() => NostrBridge.getAuthState())).toEqual({ loggedIn: false, pubkey: null });
    expect(await page.evaluate(() => NostrBridge.getSavedSession())).toBeNull();
    await expect(page.locator("#nostr-signer-container")).toHaveCSS("width", "220px");
    await expect(
      page.evaluate(() => window.nostr.signEvent({ kind: 1, created_at: 1, tags: [], content: "" })),
    ).rejects.toThrow(/not logged in/);

    // login() → signer OPEN_LOGIN → its Sign in (no clientId) → OPEN_NOSTR_SIGNER → extension.
    const signedIn = waitForAuth(page, true);
    await page.evaluate(() => NostrBridge.login());
    expect(await signedIn).toEqual({ loggedIn: true, pubkey: PUBKEY });
  });

  test("restores the session on reload", async ({ page }) => {
    await waitForAuth(page, true);
    await page.reload();
    // Known before init() is even called, so the page can render signed-in at once.
    expect(await page.evaluate(() => NostrBridge.getSavedSession())).toEqual({ pubkey: PUBKEY, mode: "wnj" });
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
    expect(await waitForAuth(page, true)).toEqual({ loggedIn: true, pubkey: PUBKEY });
  });

  test("init() is idempotent", async ({ page }) => {
    const same = await page.evaluate(
      (bunkerOrigin) => NostrBridge.init({ bunkerOrigin }) === NostrBridge.init({ bunkerOrigin }),
      BUNKER,
    );
    expect(same).toBe(true);
    await expect(page.locator("#nostr-signer-iframe")).toHaveCount(1);
  });
});

test.describe("script tag attributes", () => {
  test.withExtension();

  test("data-powered-by=\"false\" hides the library link", async ({ page, pages }) => {
    pages.set("/", `<!doctype html><html><head>
<script src="${BUNKER}/nostr-bridge.js" data-bunker-origin="${BUNKER}" data-powered-by="false"></script>
</head><body></body></html>`);
    await page.goto(APP + "/");
    await page.evaluate(() => NostrBridge.ready);
    const src = new URL(await page.locator("#nostr-signer-iframe").getAttribute("src"));
    expect(src.searchParams.get("poweredBy")).toBe("0");
  });
});

test.describe("without any sign-in method", () => {
  test("reports NO_SIGN_IN_METHOD and rejects window.nostr calls with it", async ({ page, pages }) => {
    // No extension, and window.nostr.js can't load (the CDN is offline).
    await collectSignerErrors(page);
    pages.set("/", bridgePage);
    await page.goto(APP + "/");
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);

    await expect.poll(() => page.evaluate(() => window.signerErrors.map((e) => e.code))).toEqual([
      "NO_SIGN_IN_METHOD",
    ]);
    await expect(page.evaluate(() => window.nostr.getPublicKey())).rejects.toThrow(/NO_SIGN_IN_METHOD/);
  });

  test("rejects a bunkerOrigin that is not a URL, and a corrected init() then works", async ({ page, pages }) => {
    pages.set("/", bridgePage);
    await page.goto(APP + "/");
    await expect(page.evaluate(() => NostrBridge.init({ bunkerOrigin: "nope" }))).rejects.toThrow(
      /bunkerOrigin must be an absolute URL/,
    );
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
    await expect(page.locator("#nostr-signer-iframe")).toHaveCount(1);
  });
});

test.describe("protocol handshake", () => {
  test.withExtension();

  test.describe("bridge newer than the signer", () => {
    test.use({ bridgePatch: { from: "PROTOCOL_VERSION = 1;", to: "PROTOCOL_VERSION = 99;" } });

    test("the signer refuses it with PROTOCOL_UNSUPPORTED and a hint", async ({ page, pages }) => {
      await collectSignerErrors(page);
      pages.set("/", bridgePage);
      await page.goto(APP + "/");
      await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);

      await expect.poll(() => page.evaluate(() => window.signerErrors)).toEqual([
        expect.objectContaining({
          code: "PROTOCOL_UNSUPPORTED",
          message: expect.stringContaining("protocol 99"),
          hint: expect.stringContaining("<bunkerOrigin>/nostr-bridge.js"),
        }),
      ]);
    });
  });

  test("a matching signer and bridge log no protocol warning", async ({ page, pages }) => {
    const warnings = [];
    page.on("console", (m) => m.type() === "warning" && warnings.push(m.text()));
    pages.set("/", bridgePage);
    await page.goto(APP + "/");
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
    await expect(page.locator("#nostr-signer-container")).toHaveCSS("width", "48px");
    expect(warnings.filter((w) => /protocol/i.test(w))).toEqual([]);
  });
});
