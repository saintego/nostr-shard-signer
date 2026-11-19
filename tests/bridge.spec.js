// nostr-bridge.js and signer.html together, without a clientId: sign-in goes
// through a NIP-07 extension, but every auth change still round-trips through
// the signer iframe.
import {
  test, expect, APP, BUNKER, PUBKEY, SHARED_SIGN_IN,
  bridgePage, waitForAuth, collectSignerErrors, collectSignerHellos,
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

  test("lets the signer iframe use passkeys (Evolustr)", async ({ page }) => {
    const allow = await page.locator("#nostr-signer-iframe").getAttribute("allow");
    expect(allow).toContain("publickey-credentials-get");
    expect(allow).toContain("publickey-credentials-create");
  });

  test("window.nostr.evolustr goes to the signer iframe, which identifies the page by its origin", async ({ page }) => {
    await waitForAuth(page, true);
    await expect(page.locator("#nostr-signer-container")).toHaveCSS("width", "48px");
    // The test app is on plain http: the signer refuses to give it an app key
    // (only https: origins, or http: on localhost). The answer comes from the
    // iframe, not the extension.
    await expect(page.evaluate(() => window.nostr.evolustr.capabilities())).rejects.toThrow(/https/);
    await expect(page.evaluate(() => window.nostr.evolustr.getWrapKey())).rejects.toThrow(/https/);
    expect(await page.evaluate(() => window.extensionCalls)).not.toContain("signEvent");
  });

  test("window.nostr.evolustr is refused after logout", async ({ page }) => {
    await waitForAuth(page, true);
    await page.evaluate(() => NostrBridge.logout());
    await expect(page.evaluate(() => window.nostr.evolustr.capabilities())).rejects.toThrow(/not logged in/);
  });

  test("logout() and login() round-trip through the signer iframe", async ({ page }) => {
    await waitForAuth(page, true);
    // Wait for the iframe to show the avatar (it has the session).
    await expect(page.locator("#nostr-signer-container")).toHaveCSS("width", "48px");

    await page.evaluate(() => NostrBridge.logout());
    expect(await page.evaluate(() => NostrBridge.getAuthState())).toEqual({ loggedIn: false, pubkey: null });
    expect(await page.evaluate(() => NostrBridge.getSavedSession())).toBeNull();
    await expect(page.locator("#nostr-signer-container")).toHaveCSS("width", "220px");
    // With shared sign-in, Web3Auth can't load here (no network), and the
    // error names that cause instead.
    await expect(
      page.evaluate(() => window.nostr.signEvent({ kind: 1, created_at: 1, tags: [], content: "" })),
    ).rejects.toThrow(SHARED_SIGN_IN ? /WEB3AUTH_INIT_FAILED/ : /not logged in/);

    // login() → signer OPEN_LOGIN → its Sign in (no Web3Auth) → OPEN_NOSTR_SIGNER → extension.
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
    // Nostr-only, no extension, and window.nostr.js can't load (the CDN is offline).
    await collectSignerErrors(page);
    pages.set("/", bridgePage);
    await page.goto(APP + "/");
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin, nostrOnly: true }), BUNKER);

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

test.describe("shared sign-in", () => {
  test.withExtension();

  test.beforeEach(async ({ page, pages }) => {
    await collectSignerHellos(page);
    pages.set("/", bridgePage);
  });

  test("without a clientId, the signer says whether the page gets the shared project", async ({ page }) => {
    const logs = [];
    page.on("console", (m) => logs.push(m.type() + ": " + m.text()));
    await page.goto(APP + "/");
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);

    const src = new URL(await page.locator("#nostr-signer-iframe").getAttribute("src"));
    expect(src.searchParams.get("clientId")).toBeNull();
    expect(src.searchParams.get("nostrOnly")).toBeNull();
    await expect.poll(() => page.evaluate(() => window.signerHellos.map((h) => h.oauth))).toEqual([
      SHARED_SIGN_IN ? "shared" : "none",
    ]);
    // The bridge tells the developer which one, once the signer has said so.
    await expect
      .poll(() => logs.join("\n"))
      .toMatch(
        SHARED_SIGN_IN
          ? /info: nostr-bridge: no clientId, so Google\/Apple\/X sign-in goes through the signer's shared project/
          : /warning: nostr-bridge: no clientId, so Google\/Apple\/X sign-in is off/,
      );
  });

  test("nostrOnly turns it off, also with a clientId", async ({ page }) => {
    const logs = [];
    page.on("console", (m) => logs.push(m.type() + ": " + m.text()));
    await page.goto(APP + "/");
    await page.evaluate(
      (bunkerOrigin) => NostrBridge.init({ bunkerOrigin, clientId: "some-client-id", nostrOnly: true }),
      BUNKER,
    );

    const src = new URL(await page.locator("#nostr-signer-iframe").getAttribute("src"));
    expect(src.searchParams.get("nostrOnly")).toBe("1");
    expect(src.searchParams.get("clientId")).toBeNull();
    await expect.poll(() => page.evaluate(() => window.signerHellos.map((h) => h.oauth))).toEqual(["none"]);
    expect(await waitForAuth(page, true)).toEqual({ loggedIn: true, pubkey: PUBKEY });
    const text = logs.join("\n");
    expect(text).toMatch(/nostrOnly turns Google\/Apple\/X sign-in off; ignoring clientId/);
    // A deliberate choice, so no "no clientId" notice.
    expect(text).not.toMatch(/no clientId/);
  });

  test("data-nostr-only on the script tag", async ({ page, pages }) => {
    pages.set("/", `<!doctype html><html><head>
<script src="${BUNKER}/nostr-bridge.js" data-bunker-origin="${BUNKER}" data-nostr-only="true"></script>
</head><body></body></html>`);
    await page.goto(APP + "/");
    await page.evaluate(() => NostrBridge.ready);
    const src = new URL(await page.locator("#nostr-signer-iframe").getAttribute("src"));
    expect(src.searchParams.get("nostrOnly")).toBe("1");
  });
});

test.describe("a saved Google/Apple/X session", () => {
  test("is dropped at once when the signer has no Web3Auth for the page", async ({ page, pages }) => {
    test.skip(SHARED_SIGN_IN, "this signer offers shared sign-in to pages without a clientId");
    pages.set("/", bridgePage);
    await page.goto(APP + "/");
    await page.evaluate((pubkey) => {
      localStorage.setItem("nostr-bridge:session", JSON.stringify({ pubkey, mode: "iframe" }));
    }, PUBKEY);
    await page.reload();
    const started = Date.now();
    // No clientId: the bridge keeps the session until the signer's hello says
    // it has no shared sign-in.
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
    expect(await waitForAuth(page, false)).toEqual({ loggedIn: false, pubkey: null });
    expect(await page.evaluate(() => NostrBridge.getSavedSession())).toBeNull();
    // Not after the 10 s wait for a session that is still coming back.
    expect(Date.now() - started).toBeLessThan(5000);
  });
});
