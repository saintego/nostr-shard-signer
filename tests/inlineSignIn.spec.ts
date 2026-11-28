// The global sign-in in the widget itself (#122): what stays in the widget
// and what goes to the window, and the login handed over to it.
import { expect, test } from '@playwright/test';
import { parseHandedLogin } from '../bunker/src/lib/globalPopup.ts';
import {
  afterInlineLogin,
  createInline,
  fromHanded,
  handOver,
} from '../bunker/src/lib/inlineSignIn.ts';
import { openOwn } from '../bunker/src/lib/popupFlow.ts';
import { login, SITE, world } from './flowWorld.ts';

const OTHER = 'https://other.example';
const inline = (w: ReturnType<typeof world>) => ({ ...w.deps, defer: () => {} });

test('a new user: asked here, "Create a new account" here, signed in with identity 0', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const asked = await afterInlineLogin(google, SITE, inline(w));
  expect(asked.kind).toBe('none');
  const done = await createInline(google, SITE, inline(w));
  if (done.kind !== 'signed-in') throw new Error(done.kind);
  expect(done.answer.grant.identities).toHaveLength(1);
});

test("a new user with a name and picture gets the widget's name-and-picture step", async () => {
  const w = world();
  const google = { ...login('google', 'a…@gmail.com'), profile: { name: 'Alice' } };
  const done = await createInline(google, SITE, inline(w));
  expect(done.kind).toBe('new-account');
});

test('identities already paired with the site: signed in here, no window', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const own = await openOwn(google, SITE, w.deps);
  if (own.step !== 'account') throw new Error(own.step);
  await own.account.pair(own.account.list[0]?.pubkey ?? '');
  const again = await afterInlineLogin(google, SITE, inline(w));
  if (again.kind !== 'signed-in') throw new Error(again.kind);
  expect(again.answer.grant.active).toBe(own.account.list[0]?.pubkey);
});

test('an account not used on this site yet: Welcome back, in the window, from the same login', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const own = await openOwn(google, OTHER, w.deps);
  if (own.step !== 'account') throw new Error(own.step);
  await own.account.pair(own.account.list[0]?.pubkey ?? '');
  const here = await afterInlineLogin(google, SITE, inline(w));
  if (here.kind !== 'window') throw new Error(here.kind);
  expect(fromHanded(here.login).login.key).toEqual(google.login.key);
});

test("the handed login is checked field by field; the window takes only what's valid", () => {
  const google = {
    ...login('google', 'a…@gmail.com'),
    profile: { name: 'A', picture: 'https://p.example/a.png' },
  };
  const handed = handOver(google);
  expect(parseHandedLogin(handed)).toEqual(handed);
  expect(parseHandedLogin({ ...handed, key: 'nothex' })).toBeNull();
  expect(parseHandedLogin({ ...handed, provider: 'Google<script>' })).toBeNull();
  expect(parseHandedLogin({ ...handed, picture: 'javascript:alert(1)' })).toBeNull();
  expect(parseHandedLogin(null)).toBeNull();
});
