import { defineConfig, devices } from "@playwright/test";

// Smoke tests for nostr-bridge.js, signer.html and the npm loader. They need
// the built signer (bunker/dist); `npm test` builds it first. All network is
// served from the repo by tests/fixtures.js, so no real origin is contacted.
export default defineConfig({
  testDir: "tests",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: { trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
