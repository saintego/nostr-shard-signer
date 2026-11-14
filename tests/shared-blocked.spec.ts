// The operator can block one site from shared sign-in (#65), with the built-in
// list or a list signed by the registry root key, without turning it off for
// everyone. A blocked page keeps extension and bunker sign-in.
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import { test, expect, APP, BUNKER, SHARED_SIGN_IN, bridgePage, collectSignerHellos } from "./fixtures.js";

test.describe("matching", () => {
  const load = () => import("../bunker/src/lib/shared.ts");
  const config = (blocked: string[]) => ({ clientId: "shared-id", on: true, blocked });

  test("an origin on the list gets no shared sign-in; others do", async () => {
    const { sharedClientIdForConfig } = await load();
    const c = config(["https://evil.example"]);
    expect(sharedClientIdForConfig(c, "", false, "https://evil.example")).toBe("");
    expect(sharedClientIdForConfig(c, "", false, "https://EVIL.example")).toBe("");
    expect(sharedClientIdForConfig(c, "shared-id", false, "https://evil.example")).toBe("");
    expect(sharedClientIdForConfig(c, "", false, "http://evil.example")).toBe("shared-id");
    expect(sharedClientIdForConfig(c, "", false, "https://good.example")).toBe("shared-id");
  });

  test("*.host blocks every subdomain, not the host itself or look-alikes", async () => {
    const { isOriginBlocked } = await load();
    const list = ["*.bad.example"];
    expect(isOriginBlocked("https://a.bad.example", list)).toBe(true);
    expect(isOriginBlocked("http://x.y.bad.example:8080", list)).toBe(true);
    expect(isOriginBlocked("https://bad.example", list)).toBe(false);
    expect(isOriginBlocked("https://notbad.example", list)).toBe(false);
    expect(isOriginBlocked("not a url", list)).toBe(false);
  });
});

// The rest needs a signer with shared sign-in (SHARED_CLIENT_ID set in
// bunker/src/lib/shared.ts) built with the matching options.
const builtInBlocked = (process.env.VITE_SHARED_BLOCKED_ORIGINS ?? "").split(",").includes(APP);
// A root key for the signed list; the signer must be built with its pubkey
// as VITE_ROOT_PUBKEY_HEX.
const testRootSk = process.env.BLOCKLIST_TEST_ROOT_SK ?? "";

const helloAndWarnings = async (page) => {
  await expect.poll(() => page.evaluate(() => window.signerHellos.length)).toBeGreaterThan(0);
  return page.evaluate(() => ({ hello: window.signerHellos[0], warnings: window.signerWarnings }));
};

test.describe("a blocked page", () => {
  test.skip(!SHARED_SIGN_IN, "needs a signer with shared sign-in");

  test.beforeEach(async ({ page, pages }) => {
    pages.set("/", bridgePage);
    await collectSignerHellos(page);
    await page.addInitScript((signerOrigin) => {
      window.signerWarnings = [];
      window.addEventListener("message", (e) => {
        if (e.origin === signerOrigin && e.data?.type === "SIGNER_WARNING") window.signerWarnings.push(e.data.code);
      });
    }, new URL(BUNKER).origin);
  });

  test("on the built-in list: no shared sign-in, and SHARED_BLOCKED", async ({ page }) => {
    test.skip(!builtInBlocked, `build with VITE_SHARED_BLOCKED_ORIGINS=${APP}`);
    await page.goto(APP + "/");
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
    const { hello, warnings } = await helloAndWarnings(page);
    expect(hello.oauth).toBe("none");
    expect(warnings).toContain("SHARED_BLOCKED");
  });

  test("on the signed list: no shared sign-in, and SHARED_BLOCKED", async ({ page, context }) => {
    test.skip(!testRootSk || builtInBlocked, "set BLOCKLIST_TEST_ROOT_SK and build with its pubkey as VITE_ROOT_PUBKEY_HEX");
    const sk = Uint8Array.from(testRootSk.match(/../g)!, (h) => parseInt(h, 16));
    const list = finalizeEvent({
      kind: 30078, created_at: Math.floor(Date.now() / 1000),
      tags: [["d", "nostr-shard-signer:shared-blocked"]],
      content: JSON.stringify({ origins: [APP] }),
    }, sk);
    expect(list.pubkey).toBe(getPublicKey(sk));
    // A relay that has the list (registered after the fixture's, so it wins).
    await context.routeWebSocket(/.*/, (ws) => {
      ws.onMessage((raw) => {
        const [type, subId, filter] = JSON.parse(String(raw));
        if (type !== "REQ") return;
        if (filter?.["#d"]?.includes("nostr-shard-signer:shared-blocked")) ws.send(JSON.stringify(["EVENT", subId, list]));
        ws.send(JSON.stringify(["EOSE", subId]));
      });
    });
    await page.goto(APP + "/");
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
    const { hello, warnings } = await helloAndWarnings(page);
    expect(hello.oauth).toBe("none");
    expect(warnings).toContain("SHARED_BLOCKED");
  });
});
