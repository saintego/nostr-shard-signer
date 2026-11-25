// Ending Web3Auth sessions without Web3Auth (#73 D23, #79; checks C7, C16).
import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import {
  deleteSession,
  findSession,
  GLOBAL_SESSION,
  REFRESH_COOKIE,
  type SessionEnv,
  SITE_SESSION,
  sweepGlobalSession,
  TOKEN_KEYS,
  WEB3AUTH_STATE_KEY,
} from '../bunker/src/lib/web3authSession.ts';
import { APP, BUNKER, blankPage, bridgePage, test as pageTest } from './fixtures.js';

const fakeEnv = (
  local: Record<string, string>,
  session: Record<string, string>,
  cookies: string[]
) => {
  const store = (o: Record<string, string>) => ({
    getItem: (k: string) => o[k] ?? null,
    removeItem: (k: string) => {
      delete o[k];
    },
  });
  const env: SessionEnv = {
    local: store(local),
    session: store(session),
    cookies: () => cookies.map((c) => `${c}=x`).join('; '),
    expireCookie: (name) => {
      cookies.splice(cookies.indexOf(name), 1);
    },
  };
  return env;
};

test('a global session is found and deleted without touching the site session', () => {
  const local: Record<string, string> = {
    'auth_store_global:session_id': 's',
    'auth_store_global:access_token': 'a',
    'auth_store_global:id_token': 'i',
    'auth_store:session_id': 'site',
    'Web3Auth-state': 'site-state',
  };
  const session: Record<string, string> = { 'w3a_global_Web3Auth-state': 'g' };
  const cookies = ['auth_store_global:refresh_token', 'auth_store:refresh_token'];
  const env = fakeEnv(local, session, cookies);

  expect(findSession(GLOBAL_SESSION, env)).toHaveLength(4);
  deleteSession(GLOBAL_SESSION, env);
  expect(findSession(GLOBAL_SESSION, env)).toEqual([]);
  expect(session).toEqual({});
  // The site's session is untouched.
  expect(local).toEqual({ 'auth_store:session_id': 'site', 'Web3Auth-state': 'site-state' });
  expect(cookies).toEqual(['auth_store:refresh_token']);
  expect(findSession(SITE_SESSION, env)).toEqual([
    'auth_store:session_id',
    'cookie auth_store:refresh_token',
  ]);
});

test('the sweep ends a leftover global session even when logout fails (code 5113)', async () => {
  const local: Record<string, string> = { 'auth_store_global:session_id': 's' };
  const env = fakeEnv(local, {}, []);
  const found = await sweepGlobalSession(async () => {
    throw Object.assign(new Error('Wallet is not connected'), { code: 5113 });
  }, env);
  expect(found).toEqual(['auth_store_global:session_id']);
  expect(local).toEqual({});
});

test("nothing to sweep: Web3Auth isn't asked at all", async () => {
  let called = false;
  const found = await sweepGlobalSession(
    async () => {
      called = true;
    },
    fakeEnv({}, {}, [])
  );
  expect(found).toEqual([]);
  expect(called).toBe(false);
});

// These names are Web3Auth internals: if an update renames them, the signer
// would stop finding leftover sessions. This test reads the installed SDK.
test('Web3Auth still uses the storage names the signer relies on', () => {
  const read = (p: string) =>
    readFileSync(new URL(`../node_modules/${p}`, import.meta.url), 'utf8');
  const auth = read('@web3auth/auth/dist/lib.esm/core/auth.js');
  expect(auth).toContain('"_storageBaseKey", "auth_store"');
  expect(auth).toContain('this.options.sessionKey ||');
  const types = read('@toruslabs/session-manager/dist/lib.esm/auth/types.js');
  for (const k of [...TOKEN_KEYS, REFRESH_COOKIE]) expect(types).toContain(`"${k}"`);
  const manager = read('@toruslabs/session-manager/dist/lib.esm/auth/AuthSessionManager.js');
  // biome-ignore lint/suspicious/noTemplateCurlyInString: the SDK's source text
  expect(manager).toContain('`${this.storageKeyPrefix}:${STORAGE_KEYS.SESSION_ID}`');
  expect(manager).toMatch(/refreshToken:[^\n]*new CookieStorage/);
  const constants = read('@web3auth/no-modal/dist/lib.esm/base/constants.js');
  expect(constants).toContain(`WEB3AUTH_STATE_STORAGE_KEY = "${WEB3AUTH_STATE_KEY}"`);
});

pageTest(
  'a signer popup sweeps a leftover global session from the signer origin',
  async ({ page, pages }) => {
    pages.set('signer:/blank', blankPage);
    await page.goto(`${BUNKER}/blank`);
    await page.evaluate(() => {
      localStorage.setItem('auth_store_global:session_id', 'left over');
      localStorage.setItem('auth_store_global:access_token', 'left over');
      localStorage.setItem('auth_store:session_id', 'the site session');
    });
    await page.goto(`${BUNKER}/signer.html?evolustr-passkey=1`);
    await expect
      .poll(() => page.evaluate(() => localStorage.getItem('auth_store_global:session_id')))
      .toBeNull();
    expect(
      await page.evaluate(() => localStorage.getItem('auth_store_global:access_token'))
    ).toBeNull();
    expect(await page.evaluate(() => localStorage.getItem('auth_store:session_id'))).toBe(
      'the site session'
    );
  }
);

pageTest(
  '#138: the widget sweeps a global session a sign-in left in the site’s storage',
  async ({ page, pages }) => {
    pages.set('/', bridgePage);
    await page.goto(`${APP}/`);
    // What a sign-in in the widget leaves when the tab closes before it ends:
    // put in the widget's own storage, then the widget is loaded again.
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
    const frame = () => page.frames().find((f) => f.url().includes('signer.html'));
    await expect.poll(() => !!frame()).toBe(true);
    await frame()?.evaluate(() => {
      localStorage.setItem('auth_store_global:session_id', 'left over');
      localStorage.setItem('auth_store:session_id', 'the site session');
    });
    await page.reload();
    await page.evaluate((bunkerOrigin) => NostrBridge.init({ bunkerOrigin }), BUNKER);
    await expect.poll(() => !!frame()).toBe(true);
    await expect
      .poll(() => frame()?.evaluate(() => localStorage.getItem('auth_store_global:session_id')))
      .toBeNull();
    expect(await frame()?.evaluate(() => localStorage.getItem('auth_store:session_id'))).toBe(
      'the site session'
    );
  }
);
