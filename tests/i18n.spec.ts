// Translation readiness (AGENTS.md, User-facing text): text comes from
// messages bundled with the signer; a page may only ask for a language.
import { expect, test } from '@playwright/test';
import {
  addTranslation,
  defineMessages,
  format,
  messagesFor,
  resolveLocale,
} from '../bunker/src/lib/i18n.ts';
import { APP, BUNKER, bridgePage, test as bridgeTest } from './fixtures.js';

test('resolveLocale: the page language if the signer has it, then the browser, then English', () => {
  const have = ['en', 'es', 'pt-br'];
  expect(resolveLocale('es', ['de'], have)).toBe('es');
  expect(resolveLocale('es-MX', ['de'], have)).toBe('es');
  expect(resolveLocale('pt_BR', [], have)).toBe('pt-br');
  expect(resolveLocale('fr', ['de', 'es-ES'], have)).toBe('es');
  expect(resolveLocale(null, ['de'], have)).toBe('en');
  // Only a language code is accepted from the page.
  expect(resolveLocale('es"><script>', ['de'], have)).toBe('en');
  expect(resolveLocale('es', [], ['en'])).toBe('en');
});

test('messagesFor: a translation overrides English, missing keys fall back', () => {
  const def = defineMessages('test', { title: 'Hello {name}', ok: 'OK' });
  addTranslation(def, 'es', { title: 'Hola {name}' });
  expect(messagesFor(def, 'es')).toEqual({ title: 'Hola {name}', ok: 'OK' });
  expect(messagesFor(def, 'es-MX').title).toBe('Hola {name}');
  expect(messagesFor(def, 'de')).toEqual(def.en);
  expect(format(messagesFor(def, 'es').title, { name: 'Ana' })).toBe('Hola Ana');
  expect(format('{missing} stays', {})).toBe('{missing} stays');
});

bridgeTest(
  'the bridge passes a language code to the signer, nothing else',
  async ({ page, pages }) => {
    pages.set('/', bridgePage);
    await page.goto(`${APP}/`);
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin, locale: 'es' }), BUNKER);
    const src = new URL(await page.locator('#nostr-signer-iframe').getAttribute('src'));
    expect(src.searchParams.get('locale')).toBe('es');
  }
);

bridgeTest('the bridge drops a locale that is not a language code', async ({ page, pages }) => {
  pages.set('/', bridgePage);
  await page.goto(`${APP}/`);
  await page.evaluate(
    (bunkerOrigin) => NostrBridge.init({ bunkerOrigin, locale: 'es&clientId=x' }),
    BUNKER
  );
  const src = new URL(await page.locator('#nostr-signer-iframe').getAttribute('src'));
  expect(src.searchParams.get('locale')).toBeNull();
});

bridgeTest(
  'the bridge passes globalLogin (off or require) to the signer (#83)',
  async ({ page, pages }) => {
    pages.set('/', bridgePage);
    await page.goto(`${APP}/`);
    await page.evaluate(
      (bunkerOrigin) => NostrBridge.init({ bunkerOrigin, clientId: 'x', globalLogin: 'require' }),
      BUNKER
    );
    const src = new URL(await page.locator('#nostr-signer-iframe').getAttribute('src'));
    expect(src.searchParams.get('globalLogin')).toBe('require');
  }
);
