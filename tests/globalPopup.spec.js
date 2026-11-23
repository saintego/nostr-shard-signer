// The global sign-in popup in a browser (#80). Needs shared sign-in in the
// build (SHARED_CLIENT_ID); Google itself isn't reached (tests run offline).
import { test, expect, APP, BUNKER, SHARED_SIGN_IN, bridgePage, blankPage } from "./fixtures.js";

test.skip(!SHARED_SIGN_IN, "needs shared sign-in in the build");

test("the widget's Google button opens the signer's popup, which serves only that widget", async ({ page, pages }) => {
  pages.set("/", bridgePage);
  await page.goto(`${APP}/`);
  await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
  const signer = page.frameLocator("#nostr-signer-iframe");
  await signer.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator("#nostr-signer-container")).toHaveCSS("height", "580px");
  const popupOpened = page.waitForEvent("popup");
  await signer.getByRole("button", { name: /^Continue with Google/ }).click();
  const popup = await popupOpened;
  expect(new URL(popup.url()).searchParams.get("global-signin")).toBe("1");
  // The handshake succeeded: the popup names the site the widget is on.
  await expect(popup.getByText("For app.test")).toBeVisible();
  // Closing it returns the widget to its button, without an error.
  await popup.close();
  await expect(page.locator("#nostr-signer-container")).toHaveCSS("width", "220px");
});

test("another page on the signer's origin can't use the popup", async ({ page, pages }) => {
  pages.set("signer:/other", blankPage);
  await page.goto(`${BUNKER}/other`);
  const popupOpened = page.waitForEvent("popup");
  await page.evaluate(() => {
    const w = window.open(`${location.origin}/nostr-shard-signer/signer.html?global-signin=1`, "_blank");
    window.addEventListener("message", (e) => {
      if (e.source === w && e.data?.type === "NSS_GLOBAL_READY")
        w.postMessage({ type: "NSS_GLOBAL_REQUEST", site: "https://example.com" }, location.origin);
    });
  });
  const popup = await popupOpened;
  await expect(popup.getByText("This window can only be opened from the sign-in widget on a site.")).toBeVisible();
  await expect(popup.getByRole("button", { name: "Continue with Google" })).toHaveCount(0);
});
