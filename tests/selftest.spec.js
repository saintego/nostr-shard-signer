// The production build setup (#86): derivation vectors, the patched Buffer and
// Evolu, run by bunker/selftest.html, built with the signer's Vite config and
// polyfills. Served on https (OPFS, which Evolu needs, wants a secure context).
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../bunker/dist');
const ORIGIN = 'https://signer.test';

test('derivation, Buffer and Evolu work in the production build', async ({ page, context }) => {
  await context.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== ORIGIN) return route.abort();
    const p = url.pathname.replace(/^\/nostr-shard-signer/, '');
    if (p === '/selftest.html') {
      return route.fulfill({
        contentType: 'text/html',
        body: await readFile(path.join(dist, 'selftest.html'), 'utf8'),
      });
    }
    if (p.startsWith('/assets/')) return route.fulfill({ path: path.join(dist, p) });
    return route.abort();
  });
  await context.routeWebSocket(/.*/, (ws) => ws.close());
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(`${ORIGIN}/nostr-shard-signer/selftest.html`);
  await expect.poll(() => page.evaluate(() => window.selftest), { timeout: 20000 }).toBeTruthy();
  const results = await page.evaluate(() => window.selftest);
  expect(results.map((r) => r.name)).toEqual([
    'derivation',
    'buffer',
    'evolu',
    'globalList',
    'syncedApps',
    'noPersistPrompt',
    'siteCache',
    'canary',
  ]);
  for (const r of results) expect(r, JSON.stringify(r)).toMatchObject({ ok: true });
  expect(errors).toEqual([]);
});
