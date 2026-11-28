// Several identities on one shared-sign-in site (#73 D14, #84; scenario 12):
// the popup hands over the identities paired with the site, the widget
// switches between them, and the page hears about it. Needs shared sign-in in
// the build; the popup's answer is posted by the test (Google isn't reached).

import { getPublicKey } from 'nostr-tools/pure';
import { BUNKER, bridgePage, expect, LOCAL_APP, SHARED_SIGN_IN, test } from './fixtures.js';

test.skip(!SHARED_SIGN_IN, 'needs shared sign-in in the build');

const keyA = '11'.repeat(32);
const keyB = '22'.repeat(32);
const A = getPublicKey(Buffer.from(keyA, 'hex'));
const B = getPublicKey(Buffer.from(keyB, 'hex'));

test("the widget switches between the site's identities; the page sees each switch", async ({
  context,
  page,
  pages,
}) => {
  // The window's request, so the fake answer can carry its nonce (#144).
  await context.addInitScript(() =>
    window.addEventListener('message', (e) => {
      if (e.data?.type === 'NSS_GLOBAL_REQUEST') window.lastRequest = e.data;
    })
  );
  pages.set('/', bridgePage);
  await page.goto(`${LOCAL_APP}/`);
  await page.evaluate((bunkerOrigin) => {
    window.authLog = [];
    NostrBridge.onAuthChange((s) => window.authLog.push(s.pubkey));
    return NostrBridge.init({ bunkerOrigin, signInUi: 'buttons' }); // the window path (#122)
  }, BUNKER);
  const signer = page.frameLocator('#nostr-signer-iframe');
  await signer.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.locator('#nostr-signer-container')).toHaveCSS('height', '580px');
  const popupOpened = page.waitForEvent('popup');
  await signer.getByRole('button', { name: /^Continue with Google/ }).click();
  const popup = await popupOpened;
  await expect(popup.getByText('For localhost:4173')).toBeVisible();
  // What the popup hands over after Welcome back: two identities, A active,
  // with the request's nonce (#144), caught by the init script below.
  await popup.evaluate(
    (grant) =>
      window.opener.postMessage(
        { type: 'NSS_GLOBAL_RESULT', grant, nonce: window.lastRequest?.nonce },
        location.origin
      ),
    {
      storeKey: 'ab'.repeat(32),
      identities: [
        { secretKey: keyA, pubkey: A, label: null },
        { secretKey: keyB, pubkey: B, label: 'Work' },
      ],
      active: A,
    }
  );
  await expect
    .poll(() => page.evaluate(() => window.nostr.getPublicKey().catch(() => null)))
    .toBe(A);

  // The widget finishes loading the profile from relays (offline here) first.
  await expect(async () => {
    await signer.getByRole('button', { name: 'Open Nostr profile' }).click({ timeout: 1000 });
    await expect(signer.getByText('Identities on this site')).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 15000 });
  await expect(
    signer.getByText('This site can tell that these identities belong to the same person.')
  ).toBeVisible();
  // Click only once the panel has its size (the container animates).
  await expect(page.locator('#nostr-signer-container')).toHaveCSS('height', '580px');
  await signer.getByRole('button', { name: 'Use this one' }).click();
  await expect
    .poll(() => page.evaluate(() => window.nostr.getPublicKey().catch(() => null)))
    .toBe(B);
  expect(await page.evaluate(() => window.authLog.filter(Boolean))).toEqual(
    expect.arrayContaining([A, B])
  );

  // After a reload, the cache restores the identity last used.
  await page.reload();
  await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
  await expect
    .poll(() => page.evaluate(() => window.nostr.getPublicKey().catch(() => null)))
    .toBe(B);

  // Signing out deletes this site's cache: a reload stays signed out (#117).
  await expect(async () => {
    await signer.getByRole('button', { name: 'Open Nostr profile' }).click({ timeout: 1000 });
    await signer.getByRole('button', { name: 'Log out' }).first().click({ timeout: 1000 });
  }).toPass({ timeout: 15000 });
  await expect
    .poll(() => page.evaluate(() => window.nostr.getPublicKey().catch(() => null)))
    .toBeNull();
  await page.reload();
  await page.evaluate((bunkerOrigin) => {
    window.states = [];
    NostrBridge.onAuthChange((s) => window.states.push(s.loggedIn));
    return NostrBridge.init({ bunkerOrigin });
  }, BUNKER);
  await expect.poll(() => page.evaluate(() => window.states.length)).toBeGreaterThan(0);
  expect(await page.evaluate(() => window.states.at(-1))).toBe(false);
});
