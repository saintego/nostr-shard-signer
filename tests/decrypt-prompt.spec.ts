// The decrypt prompt says when the "message" was encrypted to the user
// themselves: that is how apps keep private data and keys, and any site can
// copy such a ciphertext from the user's public events (#63).
import { test, expect, BUNKER } from "./fixtures.js";

const OWN = "a".repeat(64);
const OTHER = "b".repeat(64);

test.describe("describeRequest", () => {
  // approval.ts pulls in browser-only modules; a minimal window is enough.
  const load = async () => {
    (globalThis as Record<string, unknown>).window ??= { addEventListener() {}, removeEventListener() {} };
    return import("../bunker/src/lib/approval.ts");
  };

  test("a decrypt of data encrypted to yourself names the site and warns", async () => {
    const { describeRequest } = await load();
    for (const method of ["nip04_decrypt", "nip44_decrypt"]) {
      const d = describeRequest(method, [OWN, "ct"], { ownPubkey: OWN, site: "evil.example" });
      expect(d.title).toBe("Let evil.example read data you encrypted to yourself?");
      expect(d.warning).toMatch(/key to another app's private data/);
    }
  });

  test("a decrypt from someone else shows who, without the warning", async () => {
    const { describeRequest, shortNpub } = await load();
    const d = describeRequest("nip44_decrypt", [OTHER, "ct"], { ownPubkey: OWN, site: "chat.example" });
    expect(d.title).toBe("Let chat.example read a private message?");
    expect(d.summary).toContain(`From or to ${shortNpub(OTHER)}`);
    expect(shortNpub(OTHER)).toMatch(/^npub1.{4}….{4}$/);
    expect(d.warning).toBeUndefined();
  });
});

// A page on the signer's origin opens the confirmation popup and sends it a
// request, as the signer iframe does in shared mode.
const opener = `<!doctype html><script>
window.ask = (request) => new Promise((resolve) => {
  const w = window.open("signer.html?confirm=1", "confirm", "popup");
  addEventListener("message", (e) => {
    if (e.source !== w) return;
    if (e.data.type === "CONFIRM_POPUP_READY") w.postMessage({ type: "CONFIRM_POPUP_REQUEST", request }, location.origin);
    if (e.data.type === "CONFIRM_POPUP_ANSWER") resolve(e.data.answer);
  });
});
</script>`;

test.describe("the prompt", () => {
  test.beforeEach(async ({ page, pages }) => {
    pages.set("signer:/opener.html", opener);
    await page.goto(BUNKER + "/opener.html");
  });

  const ask = async (page, params) => {
    const popupOpened = page.waitForEvent("popup");
    await page.evaluate((request) => { window.answer = window.ask(request); }, {
      kind: "rpc", origin: "https://evil.example", method: "nip44_decrypt", params, ownPubkey: OWN,
    });
    return popupOpened;
  };

  test("shows the warning for data encrypted to yourself", async ({ page }) => {
    const popup = await ask(page, [OWN, "ct"]);
    await expect(popup.getByRole("heading")).toHaveText("Let evil.example read data you encrypted to yourself?");
    await expect(popup.getByText("This can be the key to another app's private data")).toBeVisible();
    await popup.getByRole("button", { name: "Reject" }).click();
    expect(await page.evaluate(() => window.answer)).toBe("reject");
  });

  test("names the peer for other messages", async ({ page }) => {
    const popup = await ask(page, [OTHER, "ct"]);
    await expect(popup.getByRole("heading")).toHaveText("Let evil.example read a private message?");
    await expect(popup.getByText(/From or to npub1/)).toBeVisible();
    await expect(popup.getByText("key to another app")).toHaveCount(0);
  });
});
