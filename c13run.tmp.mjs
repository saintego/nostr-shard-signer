import { chromium } from "playwright";
const ctx = await chromium.launchPersistentContext("/tmp/claude-0/-home-user/6db9c987-58ac-556b-91fb-a322f085ff82/scratchpad/c13-profile", {
  executablePath: "/opt/pw-browsers/chromium", proxy: { server: process.env.HTTPS_PROXY }, ignoreHTTPSErrors: true,
});
const p = await ctx.newPage();
await p.goto("https://preview.nostr-shard-signer.pages.dev/nostr-shard-signer/checks.html?c=C13", { timeout: 60000 });
const mode = process.argv[2] ?? "publish";
if (mode === "publish") await p.getByRole("button", { name: "Publish a test set" }).click();
else await p.getByRole("button", { name: "Re-check" }).last().click();
await p.waitForTimeout(45000);
console.log(await p.locator(".log").innerText());
await ctx.close();
