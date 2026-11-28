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
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        // The test origins are http; production is https. WebCrypto (the
        // device secret, #80) needs a secure context, so treat them as one.
        // Only the full Chromium honours this flag, not the headless shell CI
        // runs: a test that needs it serves the signer over https instead
        // (SECURE_BUNKER in tests/fixtures.js).
        launchOptions: {
          args: ["--unsafely-treat-insecure-origin-as-secure=http://signer.test"],
        },
      },
    },
  ],
});
