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
  // It opens at Manage: the identities this site uses, with Unpair (#129).
  await expect(win.getByRole('heading', { name: 'Identities on signer.test' })).toBeVisible({
    timeout: 20000,
  });
  await expect(win.getByRole('button', { name: 'Unpair' })).toBeVisible();
  await snap(win, '6 window: Manage');
  // Nothing covers the window: Done, then "Create a new identity" opens its form.
  await win.getByRole('button', { name: 'Done' }).click();
  await expect(win.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
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

test("shared mode: the widget's Keys tab doesn't show the nsec; Export key opens the window", async ({
  page,
  pages,
}) => {
  const signer = await openApp(page, pages);
  await signUp(page, signer);
  await expect(async () => {
    await signer.getByRole('button', { name: 'Open Nostr profile' }).click({ timeout: 1000 });
    await signer.getByRole('tab', { name: 'Keys' }).click({ timeout: 1000 });
  }).toPass({ timeout: 15000 });
  await expect(signer.getByText('Public key (npub)')).toBeVisible();
  // A page could cover the widget and get the user to reveal or copy it (#62, #130).
  await expect(signer.getByText('Secret key (nsec)')).toHaveCount(0);
  await expect(signer.getByRole('button', { name: /Reveal|Copy nsec/ })).toHaveCount(0);
  await snap(page, '7 keys tab');
  const opened = page.waitForEvent('popup');
  await signer.getByRole('button', { name: 'Export key' }).click();
  await opened;
});

test('Account tab: switching, Back up and Log out without scrolling; Back up opens the window at Backup', async ({
  page,
  pages,
}) => {
  const signer = await openApp(page, pages);
  await signUp(page, signer);
  await expect(async () => {
    await signer.getByRole('button', { name: 'Open Nostr profile' }).click({ timeout: 1000 });
    await expect(signer.getByRole('tab', { name: 'Account' })).toHaveAttribute(
      'aria-selected',
      'true',
      { timeout: 1000 }
    );
  }).toPass({ timeout: 15000 });
  await settled(page);
  // In view, without scrolling (#132).
  await expect(signer.getByRole('button', { name: 'Log out' })).toBeInViewport();
  await expect(signer.getByRole('button', { name: 'Back up your account' })).toBeInViewport();
  await snap(page, '8 account tab');
  const opened = page.waitForEvent('popup');
  await signer.getByRole('button', { name: 'Back up your account' }).click();
  const win = await opened;
  await win.setViewportSize(pixel.viewport);
  await win.getByRole('button', { name: 'Fake google' }).click();
  await expect(win.getByRole('heading', { name: 'Back up your account' })).toBeVisible({
    timeout: 20000,
  });
  await snap(win, '9 window: backup');
});

test("the page's NostrBridge.logout() after a reload signs out on this site (#121)", async ({
  page,
  pages,
}) => {
  let signer = await openApp(page, pages);
  await signUp(page, signer);
  await page.reload();
  signer = await openApp(page, pages);
  await expect.poll(() => pubkey(page), { timeout: 15000 }).not.toBeNull();
  await page.evaluate(() => NostrBridge.logout());
  await expect.poll(() => pubkey(page)).toBeNull();
  await page.reload();
  signer = await openApp(page, pages);
  await expect(signer.getByRole('button', { name: 'Sign in' })).toBeVisible();
  expect(await pubkey(page)).toBeNull();
});

test('the canary (#91): a site added to the shared project pauses new sign-ins', async ({
  page,
  pages,
}) => {
  // The shared project's public configuration (C15), with one unexpected site.
  await page.route('https://api.web3auth.io/signer-service/api/v2/configuration**', (route) =>
    route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({
        enableKeyExport: true,
        whitelist: { urls: [SECURE_SIGNER_ORIGIN, 'https://evil.example'], signed_urls: {} },
      }),
    })
  );
  const signer = await openApp(page, pages);
  await signer.getByRole('button', { name: 'Sign in' }).click();
  await expect(signer.getByText('Sign-in paused')).toBeVisible();
  await expect(signer.getByRole('dialog', { name: 'Web3Auth sign-in' })).toHaveCount(0);
  await snap(page, 'canary paused');
  expect(await pubkey(page)).toBeNull();
});

test('#134: "Create a new account" and "Continue" ignore clicks until they are armed', async ({
  page,
  pages,
}) => {
  const signer = await openApp(page, pages);
  await signer.getByRole('button', { name: 'Sign in' }).click();
  await signer.getByRole('button', { name: 'Fake google' }).click();
  const create = signer.getByRole('button', { name: 'Create a new account' });
  await expect(create).toBeVisible();
  // Right after the step appears: disabled, so a click the user didn't see does nothing.
  await expect(create).toHaveAttribute('data-armed', 'false');
  await expect(create).toHaveAttribute('data-armed', 'true');
  await create.click();
  const next = signer.getByRole('button', { name: 'Continue' });
  await expect(next).toBeVisible();
  await expect(next).toHaveAttribute('data-armed', 'false');
  await expect(next).toHaveAttribute('data-armed', 'true');
});

test('#66: app keys in shared mode name the shared sign-in, and adding a passkey promises nothing more', async ({
  page,
  pages,
}) => {
  const signer = await openApp(page, pages);
  await signUp(page, signer);
  // An app asks for its own key: the choice opens in the signer's window (#62).
  void page.evaluate(() => window.nostr.evolustr.getWrapKey().catch(() => {}));
  const opened = page.waitForEvent('popup');
  await signer.getByRole('button', { name: 'Review this request' }).click();
  const popup = await opened;
  await expect(popup.getByText(/whoever runs the shared sign-in you used/)).toBeVisible();
  await expect(popup.getByText(/this site's Web3Auth project/)).toHaveCount(0);
  await expect(
    popup.getByText('This choice can’t be changed later for data you already have.')
  ).toBeVisible();
  await popup.getByRole('button', { name: 'With my login' }).click();
  await expect(async () => {
    await signer.getByRole('button', { name: 'Open Nostr profile' }).click({ timeout: 1000 });
    await signer.getByRole('tab', { name: 'Settings' }).click({ timeout: 1000 });
  }).toPass({ timeout: 15000 });
  await expect(
    signer.getByText(/whoever runs the shared sign-in you used could recover keys/)
  ).toBeVisible({
    timeout: 15000,
  });
  await expect(signer.getByText(/doesn’t take their access away/)).toBeVisible();
  await expect(signer.getByRole('button', { name: 'Add a passkey' })).toBeVisible();
  await expect(signer.getByText(/with you alone/)).toHaveCount(0);
  await expect(signer.getByRole('button', { name: /passkey instead/ })).toHaveCount(0);
});
