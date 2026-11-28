// The sign-in window's flow with several sign-ins (#73 D25, review 8; #98):
// a new login, linking, signing in through a link, and unlinking.
import { expect, test } from '@playwright/test';
import { afterLogin, openOwn } from '../bunker/src/lib/popupFlow.ts';
import { login, SITE, world } from './flowWorld.ts';

test('a new user: nothing found, then "Create a new account" gives identity 0 and a counter event', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const step = await afterLogin(google, SITE, w.deps);
  expect(step).toMatchObject({ step: 'question', kind: 'none', wasUnlinked: false });
  const created = await openOwn(google, SITE, w.deps);
  if (created.step !== 'account') throw new Error(created.step);
  expect(created.account.isNew).toBe(true);
  const first = created.account.list[0];
  await created.account.pair(first?.pubkey ?? '');
  // A witness on relays from day one (review 8, item 4).
  expect(
    w.relay.some(
      (e) => e.kind === 30078 && e.tags.some((t) => t[1] === 'nostr-shard-signer/counter')
    )
  ).toBe(true);
  // Signing in again: its own account, Welcome back.
  expect((await afterLogin(google, SITE, w.deps)).step).toBe('account');
});

test('scenario 57: Apple on a new phone, then Google, then Apple is linked and opens the same identities', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const own = await openOwn(google, SITE, w.deps);
  if (own.step !== 'account') throw new Error(own.step);
  await own.account.pair(own.account.list[0]?.pubkey ?? '');
  const identity0 = own.account.list[0]?.pubkey;

  const apple = login('apple', 'a…@icloud.com');
  expect((await afterLogin(apple, SITE, w.deps)).step).toBe('question');
  // "Sign in with Google": the account; then link Apple to it.
  const viaGoogle = await afterLogin(google, SITE, w.deps);
  if (viaGoogle.step !== 'account') throw new Error(viaGoogle.step);
  await viaGoogle.account.link(apple.login, 'full');
  expect(viaGoogle.account.links.map((l) => l.provider)).toEqual(['apple']);

  const viaApple = await afterLogin(apple, SITE, w.deps);
  if (viaApple.step !== 'account') throw new Error(viaApple.step);
  expect(viaApple.createdWith).toEqual({ provider: 'google', masked: 'a…@gmail.com' });
  expect(viaApple.account.list[0]?.pubkey).toBe(identity0);
});

test('scenario 58: unlinked from the Google session; Apple then gets "unlinked" (honest signer)', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const own = await openOwn(google, SITE, w.deps);
  if (own.step !== 'account') throw new Error(own.step);
  await own.account.pair(own.account.list[0]?.pubkey ?? '');
  const apple = login('apple', 'a…@icloud.com');
  await own.account.link(apple.login, 'full');
  const pointer = own.account.links[0]?.pointerPubkey ?? '';
  await own.account.unlink(pointer);
  expect(own.account.links[0]?.unlinkedAt).not.toBeNull();
  // The pointer now says "unlinked": Apple finds nothing (and is told it was unlinked).
  expect(await afterLogin(apple, SITE, w.deps)).toMatchObject({
    step: 'question',
    kind: 'none',
    wasUnlinked: true,
  });
});

test('scenario 63: a restricted link opens only its identities, through the flow', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const own = await openOwn(google, SITE, w.deps);
  if (own.step !== 'account') throw new Error(own.step);
  await own.account.pair(own.account.list[0]?.pubkey ?? '');
  const created = await own.account.create('Work');
  const facebook = login('facebook', 'a…');
  await own.account.link(facebook.login, [created.pubkey]);
  const step = await afterLogin(facebook, SITE, w.deps);
  if (step.step !== 'restricted') throw new Error(step.step);
  expect(step.envelope.identities.map((i) => i.pubkey)).toEqual([created.pubkey]);
  const { restrictedGrant } = await import('../bunker/src/lib/linking.ts');
  const grant = await restrictedGrant(step.envelope, SITE, created.pubkey);
  expect(grant.identities.map((i) => i.pubkey)).toEqual([created.pubkey]);
  // Its per-site store isn't the full account's.
  const full = await own.account.grant(own.account.list[0]?.pubkey ?? '');
  expect(grant.storeKey).not.toBe(full.storeKey);
});

test('scenario 59: offline means "couldn\'t check", not a new account', async () => {
  const w = world();
  w.offline();
  expect(await afterLogin(login('apple', 'a…'), SITE, w.deps)).toMatchObject({
    step: 'question',
    kind: 'unknown',
  });
});

test('#142: a linked sign-in missing from the synced list is listed again, and can be unlinked', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const own = await openOwn(google, SITE, w.deps);
  if (own.step !== 'account') throw new Error(own.step);
  await own.account.pair(own.account.list[0]?.pubkey ?? '');
  const apple = login('apple', 'a…@icloud.com');
  await own.account.link(apple.login, 'full');
  w.dropLinks();

  const viaApple = await afterLogin(apple, SITE, w.deps);
  if (viaApple.step !== 'account') throw new Error(viaApple.step);
  expect(viaApple.account.relistedLink).toEqual({ provider: 'apple', masked: 'a…@icloud.com' });
  const listed = viaApple.account.links;
  expect(listed.map((l) => [l.provider, l.version])).toEqual([['apple', 1]]);
  // Unlinking it works: Apple then finds the link was removed.
  await viaApple.account.unlink(listed[0]?.pointerPubkey ?? '');
  expect(await afterLogin(apple, SITE, w.deps)).toMatchObject({
    step: 'question',
    wasUnlinked: true,
  });
  // Listed once: signing in with Google shows it, without a second copy.
  const viaGoogle = await afterLogin(google, SITE, w.deps);
  if (viaGoogle.step !== 'account') throw new Error(viaGoogle.step);
  expect(viaGoogle.account.relistedLink).toBeNull();
});

test('#138: in the site’s frame, the account keeps only what this site needs', async () => {
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const own = await openOwn(google, SITE, w.deps);
  if (own.step !== 'account') throw new Error(own.step);
  await own.account.pair(own.account.list[0]?.pubkey ?? '');
  await own.account.link(login('apple', 'a…@icloud.com').login, 'full');
  const before = w.relay.length;
  const inWidget = await afterLogin(google, SITE, { ...w.deps, scope: 'site' });
  if (inWidget.step !== 'account') throw new Error(inWidget.step);
  expect(inWidget.account.links).toEqual([]); // no link records (pointer keys, owners)
  expect(w.relay.length).toBe(before); // no pointers re-sent from the site's frame
  expect(inWidget.account.paired).toHaveLength(1);
  // The window still opens the whole account.
  const inWindow = await afterLogin(google, SITE, w.deps);
  if (inWindow.step !== 'account') throw new Error(inWindow.step);
  expect(inWindow.account.links.map((l) => l.provider)).toEqual(['apple']);
});

test('#145: identities opened by a restricted link count as used elsewhere; the grant says so', async () => {
  const { parseSiteGrant } = await import('../bunker/src/lib/siteGrant.ts');
  const w = world();
  const google = login('google', 'a…@gmail.com');
  const own = await openOwn(google, SITE, w.deps);
  if (own.step !== 'account') throw new Error(own.step);
  const id0 = own.account.list[0]?.pubkey ?? '';
  await own.account.pair(id0);
  expect((await own.account.grant(id0)).identities[0]?.usedElsewhere).toBeUndefined();
  await own.account.link(login('apple', 'a…@icloud.com').login, [id0]);
  expect(own.account.list[0]?.usedElsewhere).toBe(true);
  const grant = await own.account.grant(id0);
  expect(grant.identities[0]?.usedElsewhere).toBe(true);
  // The widget reads it back from the answer (and its cache) unchanged.
  expect(parseSiteGrant(JSON.parse(JSON.stringify(grant)))?.identities[0]?.usedElsewhere).toBe(
    true
  );
});
