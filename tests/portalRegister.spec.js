// The portal's Register tab (#68): two steps, the second signed by the
// connected key; and the registrar's answers shown as text only (#67).
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { APP, expect, PUBKEY, test } from './fixtures.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const REGISTRAR = 'https://nostr-shard-registrar.nostr-shard-signer.workers.dev';

test.withExtension();

test("Register asks for a challenge, signs it, and shows the registrar's answer as text", async ({
  page,
}) => {
  await page.route(`${APP}/**`, (route) => {
    const p = new URL(route.request().url()).pathname;
    if (p === '/portal/') return route.fulfill({ path: path.join(root, 'portal/index.html') });
    if (p === '/nostr-shard-signer/site-config.js')
      return route.fulfill({ path: path.join(root, 'site-config.js') });
    return route.abort();
  });
  const bodies = [];
  await page.route(`${REGISTRAR}/register`, (route) => {
    const body = JSON.parse(route.request().postData() ?? '{}');
    bodies.push(body);
    if (!body.nonce)
      return route.fulfill({ json: { ok: true, nonce: 'n'.repeat(64), expiresIn: 300 } });
    return route.fulfill({
      status: 403,
      json: { error: '<img src=x onerror="window.pwned=1"> refused' },
    });
  });

  await page.goto(`${APP}/portal/`);
  await page.fill('#reg-client-id', 'client-abc');
  await page.fill('#reg-domain', 'https://app.example.com');
  await page.click('#btn-register');

  const result = page.locator('#result-register');
  await expect(result).toContainText('<img src=x onerror="window.pwned=1"> refused');
  await expect(result.locator('img')).toHaveCount(0);
  expect(await page.evaluate(() => window.pwned)).toBeUndefined();

  expect(bodies).toHaveLength(2);
  expect(bodies[0]).toMatchObject({ clientId: 'client-abc', domain: 'https://app.example.com' });
  expect(bodies[0].nonce).toBeUndefined();
  expect(bodies[1].nonce).toBe('n'.repeat(64));
  expect(bodies[1].signedEvent).toMatchObject({
    kind: 27235,
    content: 'n'.repeat(64),
    pubkey: PUBKEY,
  });
  expect(await page.evaluate(() => window.extensionCalls)).toContain('signEvent');
});
