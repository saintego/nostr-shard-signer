// The whole shared sign-in at phone size, with the test build's fake Web3Auth
// (#127): the widget, the sign-in window, and what a user sees and can tap.
// Each state's screenshot is attached to the test's results.
//
// The site runs on the signer's own origin (as on the preview), so the widget
// and the window share the test build's Evolu stores, which stay on the device
// with sync off. Real users always go through memory and Evolu's sync: that
// part, and a second site, aren't covered here.
import { devices } from '@playwright/test';
import { expect, SECURE_BUNKER, SECURE_SIGNER_ORIGIN, test } from './fixtures.js';

const { defaultBrowserType: _, ...pixel } = devices['Pixel 7'];
test.use({ ...pixel, signerBuild: 'dist-fake', fakeRelays: true });

const appPage = `<!doctype html><html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="${SECURE_BUNKER}/nostr-bridge.js"></script>
</head><body><p>App</p></body></html>`;

async function openApp(page, pages) {
  pages.set('signer:/app', appPage);
  await page.goto(`${SECURE_SIGNER_ORIGIN}/app`);
  await page.evaluate((bunkerOrigin) => {
    window.auth = [];
    NostrBridge.onAuthChange((s) => window.auth.push(s.pubkey));
    return NostrBridge.init({ bunkerOrigin });
  }, SECURE_BUNKER);
  return page.frameLocator('#nostr-signer-iframe');
}

const pubkey = (page) => page.evaluate(() => window.nostr.getPublicKey().catch(() => null));

/** Waits until the widget's size stops changing (it's animated). */
async function settled(page) {
  const box = page.locator('#nostr-signer-container');
  if (!(await box.count())) return;
  let last = '';
  await expect
    .poll(async () => {
      const now = JSON.stringify(await box.boundingBox());
      const same = now === last;
      last = now;
      return same;
    })
    .toBe(true);
}

/** A screenshot once the widget has settled, attached and saved in the test's output folder. */
async function snap(page, name) {
  await settled(page);
  const body = await page.screenshot({ path: test.info().outputPath(`${name}.png`) });
  await test.info().attach(name, { body, contentType: 'image/png' });
}

/** Signs in a new user in the widget: the panel, "Create a new account", name and picture. */
async function signUp(page, signer) {
  await signer.getByRole('button', { name: 'Sign in' }).click();
  const panel = signer.getByRole('dialog', { name: 'Web3Auth sign-in' });
  await expect(panel).toBeVisible();
  await snap(page, '1 panel in the widget');
  await panel.getByRole('button', { name: 'Fake google' }).click();
  await expect(signer.getByText('No account uses this Google sign-in yet')).toBeVisible();
  await snap(page, '2 no account yet');
  await signer.getByRole('button', { name: 'Create a new account' }).click();
  await expect(signer.getByText('Your Nostr account is ready')).toBeVisible();
  await snap(page, '3 name and picture');
  await signer.getByRole('button', { name: 'Continue' }).click();
  await expect.poll(() => pubkey(page), { timeout: 15000 }).not.toBeNull();
  await snap(page, '4 signed in');
}

async function logOut(page, signer) {
  await expect(async () => {
    await signer.getByRole('button', { name: 'Open Nostr profile' }).click({ timeout: 1000 });
    await signer.getByRole('button', { name: 'Log out' }).first().click({ timeout: 1000 });
  }).toPass({ timeout: 15000 });
  await expect.poll(() => pubkey(page)).toBeNull();
}

test('a new user signs up in the widget, without the window', async ({ page, pages }) => {
  const popups = [];
  page.on('popup', (p) => popups.push(p));
  const signer = await openApp(page, pages);
  await signUp(page, signer);
  expect(popups).toHaveLength(0);
});

test('log out, reload: still signed out; sign in again: straight in the widget', async ({
  page,
  pages,
}) => {
  const popups = [];
  page.on('popup', (p) => popups.push(p));
  let signer = await openApp(page, pages);
  await signUp(page, signer);
  const first = await pubkey(page);
  await logOut(page, signer);
  await page.reload();
  signer = await openApp(page, pages);
  await expect(signer.getByRole('button', { name: 'Sign in' })).toBeVisible();
  expect(await pubkey(page)).toBeNull();
  await snap(page, '5 signed out after reload');
  // Returning: the site already uses this identity, so no window.
  await signer.getByRole('button', { name: 'Sign in' }).click();
  await signer.getByRole('button', { name: 'Fake google' }).click();
  await expect.poll(() => pubkey(page), { timeout: 20000 }).toBe(first);
  expect(popups).toHaveLength(0);
});

test('Add or manage identities: the window signs in, and its buttons respond', async ({
  page,
  pages,
}) => {
  const signer = await openApp(page, pages);
  await signUp(page, signer);
  await expect(async () => {
    await signer.getByRole('button', { name: 'Open Nostr profile' }).click({ timeout: 1000 });
    await expect(signer.getByRole('button', { name: 'Add or manage identities' })).toBeVisible({
      timeout: 1000,
    });
  }).toPass({ timeout: 15000 });
  const opened = page.waitForEvent('popup');
  await signer.getByRole('button', { name: 'Add or manage identities' }).click();
  const win = await opened;
  await win.setViewportSize(pixel.viewport);
  // The window opens Web3Auth's panel by itself; its button must be tappable.
  await win.getByRole('button', { name: 'Fake google' }).click();
  await expect(win.getByRole('heading', { name: 'Welcome back' })).toBeVisible({ timeout: 20000 });
  await snap(win, '6 window: Welcome back');
  // Nothing covers the window: "Create a new identity" opens its form.
  await win.getByRole('button', { name: 'Create a new identity' }).click();
  await expect(win.getByRole('heading', { name: 'A new identity' })).toBeVisible();
});

test('Sign in: no empty panel while Web3Auth loads; the widget waits button-sized', async ({
  page,
  pages,
}) => {
  const signer = await openApp(page, pages);
  // Web3Auth takes a while to load its project (here 1.5 s).
  await page.evaluate(() => localStorage.setItem('fake-w3a-init-ms', '1500'));
  await signer.getByRole('button', { name: 'Sign in' }).click();
  await page.waitForTimeout(700);
  await snap(page, '0 while Web3Auth loads');
  const box = await page.locator('#nostr-signer-container').boundingBox();
  expect(box?.height ?? 0).toBeLessThan(100);
  await expect(signer.getByRole('dialog', { name: 'Web3Auth sign-in' })).toBeVisible();
});
