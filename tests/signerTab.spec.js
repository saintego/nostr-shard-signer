// The signer in its own tab (#90, #73 D24): opened from the widget, it
// handshakes with it, shows this site's prompts while open, and stops when the
// widget goes away.
import { test, expect, BUNKER, LOCAL_APP, bridgePage, waitForAuth } from "./fixtures.js";

test.withExtension();

test("the tab connects to the widget, takes its prompts, and stops when the site closes", async ({ page, pages, context }) => {
  pages.set("/", bridgePage);
  await page.goto(`${LOCAL_APP}/`);
  await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
  await waitForAuth(page, true);
  const signer = page.frameLocator("#nostr-signer-iframe");
  // The widget may still be settling after sign-in (profile from relays): retry the click.
  await expect(async () => {
    await signer.getByRole("button", { name: "Open Nostr profile" }).click({ timeout: 1000 });
    await expect(page.locator("#nostr-signer-container")).toHaveCSS("height", "580px", { timeout: 1000 }); // the panel's size
  }).toPass({ timeout: 15000 });

  const tabOpened = context.waitForEvent("page");
  await signer.getByRole("button", { name: "Open in a new tab" }).click();
  const tab = await tabOpened;
  expect(new URL(tab.url()).searchParams.get("signer-tab")).toBe("1");
  await expect(tab.getByText("Connected to the widget on localhost:4173")).toBeVisible();

  // A prompt now shows in the tab, not in the widget.
  await page.evaluate(() => {
    window.keyAnswer = window.nostr.evolustr.getWrapKey().then(() => "key", (e) => `error: ${e.message}`);
  });
  await tab.getByRole("button", { name: "Don't allow" }).click();
  expect(await page.evaluate(() => window.keyAnswer)).toMatch(/didn't allow/);
  // The tab stays open for the next request.
  await expect(tab.getByText("Connected to the widget on localhost:4173")).toBeVisible();

  // The site's page goes away: the tab stops.
  await page.close();
  await expect(tab.getByText("The widget closed. You can close this tab.")).toBeVisible();
});
