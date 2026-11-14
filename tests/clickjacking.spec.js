// The embedding page can't make one click approve something the user didn't see
// (#62): no nested framing, guarded buttons, and, in shared mode (or with
// VITE_POPUP_CONFIRM=always), sensitive prompts in a top-level popup.
//
// Prompts come from window.nostr.evolustr: the signer asks before giving an app
// its key, also when signing goes through a NIP-07 extension, so no Google
// sign-in is needed. Its app is on localhost, the only plain-http origin that
// gets app keys.
import {
  test, expect, APP, BUNKER, FRAMER, LOCAL_APP, SHARED_SIGN_IN,
  bridgePage, waitForAuth, collectSignerErrors,
} from "./fixtures.js";

// Built with prompts in a popup: shared sign-in, or VITE_POPUP_CONFIRM=always
// (`VITE_POPUP_CONFIRM=always npm test` builds and tests that way).
const POPUP_PROMPTS = SHARED_SIGN_IN || process.env.VITE_POPUP_CONFIRM === "always";

test.describe("a third site framing the app", () => {
  test.withExtension();

  test("the signer refuses with NESTED_FRAME", async ({ page, pages }) => {
    pages.set("/", bridgePage);
    pages.set("framer:/", `<!doctype html><iframe src="${APP}/" width="600" height="400"></iframe>`);
    await collectSignerErrors(page);
    await page.goto(FRAMER + "/");
    const app = page.frame({ url: APP + "/" });
    await expect.poll(() => app?.url()).toBe(APP + "/");
    await app.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
    await expect.poll(() => app.evaluate(() => window.signerErrors.map((e) => e.code)))
      .toContain("NESTED_FRAME");
  });
});

test.describe("prompts", () => {
  test.withExtension();

  test.beforeEach(async ({ page, pages }) => {
    pages.set("/", bridgePage);
    await page.goto(LOCAL_APP + "/");
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
    await waitForAuth(page, true);
    await expect(page.locator("#nostr-signer-container")).toHaveCSS("width", "48px");
    // Ask for an app key; the answer is kept in window.keyAnswer.
    await page.evaluate(() => {
      window.keyAnswer = window.nostr.evolustr.getWrapKey().then(
        () => "key",
        (e) => "error: " + e.message,
      );
    });
  });

  const signer = (page) => page.frameLocator("#nostr-signer-iframe");

  test("approve buttons react only after a delay, and not while the iframe is hidden", async ({ page }) => {
    test.skip(POPUP_PROMPTS, "this build shows the app-key prompt in a popup");
    const approve = signer(page).locator("#view-confirm .btn-primary").first();
    await expect(approve).toBeVisible();
    await expect(approve).toBeDisabled();
    await expect(approve).toBeEnabled({ timeout: 3000 });
    // The host page makes the iframe nearly transparent: Chromium no longer
    // vouches that the button is visible.
    await page.locator("#nostr-signer-iframe").evaluate((el) => (el.style.opacity = "0.01"));
    await expect(approve).toBeDisabled();
    await page.locator("#nostr-signer-iframe").evaluate((el) => (el.style.opacity = ""));
    await expect(approve).toBeEnabled({ timeout: 3000 });
  });

  test("resizing the iframe starts the delay again", async ({ page }) => {
    const button = signer(page).locator("#view-confirm .btn-primary").first();
    await expect(button).toBeEnabled({ timeout: 3000 });
    await page.locator("#nostr-signer-iframe").evaluate((el) => (el.style.height = el.offsetHeight + 40 + "px"));
    await expect(button).toBeDisabled();
    await expect(button).toBeEnabled({ timeout: 3000 });
  });

  test.describe("in a popup", () => {
    test.skip(!POPUP_PROMPTS, "needs shared sign-in or a build with VITE_POPUP_CONFIRM=always");

    test("the iframe only offers to review; the answer comes from the popup", async ({ page }) => {
      const review = signer(page).locator("#review-request");
      await expect(review).toBeEnabled({ timeout: 3000 });
      await expect(signer(page).getByText("Create passkey")).toHaveCount(0);
      const popupOpened = page.waitForEvent("popup");
      await review.click();
      const popup = await popupOpened;
      await popup.getByRole("button", { name: "Don't allow" }).click();
      expect(await page.evaluate(() => window.keyAnswer)).toMatch(/didn't allow/);
    });

    test("allowing in the popup lets the signer go on", async ({ page }) => {
      const review = signer(page).locator("#review-request");
      await expect(review).toBeEnabled({ timeout: 3000 });
      const popupOpened = page.waitForEvent("popup");
      await review.click();
      const popup = await popupOpened;
      await popup.getByRole("button", { name: "Create passkey" }).click();
      // The signer goes on to read its key vault, which fails offline: the
      // answer was "allow", not a refusal.
      const answer = await page.evaluate(() => window.keyAnswer);
      expect(answer).not.toMatch(/didn't allow/);
      expect(answer).toMatch(/relay/);
    });

    test("closing the popup rejects", async ({ page }) => {
      const review = signer(page).locator("#review-request");
      await expect(review).toBeEnabled({ timeout: 3000 });
      const popupOpened = page.waitForEvent("popup");
      await review.click();
      const popup = await popupOpened;
      await popup.getByRole("button", { name: "Don't allow" }).waitFor();
      await popup.close();
      expect(await page.evaluate(() => window.keyAnswer)).toMatch(/didn't allow/);
    });
  });
});
