// The trust rule (#73 D13, #85): scenarios 19–24 of #73 and the base cases.
import { expect, test } from '@playwright/test';
import { addedEntries, FUTURE_SKEW_S, type TrustContext, trustDecision } from '../bunker/src/lib/trustRule.ts';

const NOW = 1_700_000_000;
const ctx = (o: Partial<TrustContext> = {}): TrustContext => ({
  autoApproveKinds: new Set([1, 7, 10003, 30003, 30078, 10000, 10001]),
  isProtected: false,
  isAllowedUpload: false,
  usedElsewhere: false,
  trusted: false,
  current: null,
  lastSignedId: undefined,
  addedBySite: new Set(),
  now: NOW,
  ...o,
});
const evt = (kind: number, tags: string[][] = [], content = '', created_at = NOW) => ({ kind, tags, content, created_at });
const bookmarks = (...ids: string[]) => ids.map((id) => ['e', id]);

test('regular allowlisted kinds sign; others ask', () => {
  expect(trustDecision(evt(1), ctx())).toEqual({ action: 'sign' });
  expect(trustDecision(evt(4), ctx())).toEqual({ action: 'ask', reason: 'not-allowlisted' });
});

test('always ask: profile, follows, deletes, relay lists, relay and Blossom auth, NIP-98 elsewhere', () => {
  for (const k of [0, 3, 5, 10002, 22242, 24242]) expect(trustDecision(evt(k), ctx({ autoApproveKinds: new Set([k]) })).action).toBe('ask');
  expect(trustDecision(evt(27235), ctx({ autoApproveKinds: new Set([27235]) })).action).toBe('ask');
  expect(trustDecision(evt(27235), ctx({ autoApproveKinds: new Set([27235]), isAllowedUpload: true })).action).toBe('sign');
});

test('scenario 23: a far-future date is refused', () => {
  expect(trustDecision(evt(1, [], '', NOW + FUTURE_SKEW_S + 1), ctx())).toEqual({ action: 'refuse', reason: 'future' });
  expect(trustDecision(evt(1, [], '', NOW + FUTURE_SKEW_S), ctx()).action).toBe('sign');
});

test('scenario 24: kind 62 has its own warning', () => {
  expect(trustDecision(evt(62), ctx({ autoApproveKinds: new Set([62]) }))).toEqual({ action: 'ask', reason: 'vanish' });
});

test('replaceable data: silent when nothing exists or this site wrote last', () => {
  const current = { id: 'x', tags: [['d', 'a']], content: 'old' };
  expect(trustDecision(evt(30078, [['d', 'a']]), ctx({ current: null })).action).toBe('sign');
  expect(trustDecision(evt(30078, [['d', 'a']]), ctx({ current, lastSignedId: 'x' })).action).toBe('sign');
  expect(trustDecision(evt(30078, [['d', 'a']]), ctx({ current, lastSignedId: 'y' }))).toEqual({ action: 'ask', reason: 'not-last-writer' });
  // Relays didn't answer: treated as "exists".
  expect(trustDecision(evt(30078, [['d', 'a']]), ctx({ current: undefined }))).toEqual({ action: 'ask', reason: 'unknown-current' });
  // Trusted for this site.
  expect(trustDecision(evt(30078, [['d', 'a']]), ctx({ current, trusted: true })).action).toBe('sign');
});

test('protected (Evolustr vault) and used-elsewhere identities ask', () => {
  expect(trustDecision(evt(30078), ctx({ isProtected: true }))).toEqual({ action: 'ask', reason: 'protected' });
  expect(trustDecision(evt(30078, [['d', 'a']]), ctx({ usedElsewhere: true }))).toEqual({ action: 'ask', reason: 'used-elsewhere' });
});

test('scenario 22: an expiration tag on replaceable data asks; mute list changes ask', () => {
  expect(trustDecision(evt(30078, [['d', 'a'], ['expiration', '1']]), ctx()).action).toBe('ask');
  expect(trustDecision(evt(10000, [['p', 'x']]), ctx())).toEqual({ action: 'ask', reason: 'sensitive-list' });
});

test('scenario 19: a site that added one bookmark can remove it, not empty the list', () => {
  const current = { id: 'x', tags: bookmarks('a', 'b', 'mine'), content: '' };
  const removeMine = evt(10003, bookmarks('a', 'b'));
  expect(trustDecision(removeMine, ctx({ current, addedBySite: new Set(['e:mine']) })).action).toBe('sign');
  expect(trustDecision(evt(10003, []), ctx({ current, addedBySite: new Set(['e:mine']) }))).toEqual({ action: 'ask', reason: 'list-removal' });
  // Additions are silent.
  expect(trustDecision(evt(10003, bookmarks('a', 'b', 'mine', 'new')), ctx({ current })).action).toBe('sign');
});

test("scenario 20: an entry already in the list doesn't count as added by the site", () => {
  const current = { id: 'x', tags: bookmarks('a'), content: '' };
  expect(addedEntries(current, evt(10003, bookmarks('a', 'b')))).toEqual(['e:b']);
});

test('scenario 21: private entries are compared too; unreadable ones ask', () => {
  const current = { id: 'x', tags: [], content: 'ciphertext' };
  const next = evt(10003, [], 'ciphertext2');
  expect(trustDecision(next, ctx({ current, privateEntries: { before: ['e:a', 'e:b'], after: ['e:a', 'e:b', 'e:c'] } })).action).toBe('sign');
  expect(trustDecision(next, ctx({ current, privateEntries: { before: ['e:a', 'e:b'], after: ['e:a'] } }))).toEqual({ action: 'ask', reason: 'list-removal' });
  expect(trustDecision(next, ctx({ current, privateEntries: null }))).toEqual({ action: 'ask', reason: 'private-unreadable' });
});

test('scenario 24: the kind 62 prompt warns about everything, Evolustr data included', async () => {
  (globalThis as Record<string, unknown>).window ??= { addEventListener() {}, removeEventListener() {} };
  const { describeRequest } = await import('../bunker/src/lib/approval.ts');
  const d = describeRequest('sign_event', [JSON.stringify({ kind: 62, tags: [], content: '' })]);
  expect(d.title).toBe('Ask relays to delete everything you published?');
  expect(d.warning).toContain('Evolustr');
});
