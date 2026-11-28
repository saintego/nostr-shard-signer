// Waiting for enough answers, not all (#111).
import { expect, test } from '@playwright/test';
import { firstAnswers } from '../bunker/src/lib/quorum.ts';

const after =
  <T>(ms: number, value: T) =>
  () =>
    new Promise<T>((r) => setTimeout(() => r(value), ms));
const failing = (ms: number) => () =>
  new Promise<never>((_, reject) => setTimeout(() => reject(new Error('down')), ms));
const never = () => new Promise<never>(() => {});

test('resolves once the quorum answered, without waiting for a slow one', async () => {
  const start = Date.now();
  const answers = await firstAnswers(
    [after(10, 'a'), after(20, 'b'), never, after(5000, 'slow')],
    2,
    4000
  );
  expect(answers.sort()).toEqual(['a', 'b']);
  expect(Date.now() - start).toBeLessThan(1000);
});

test('failures do not count; all finished ends it early; the cap ends it otherwise', async () => {
  expect(await firstAnswers([after(5, 'a'), failing(5), failing(10)], 2, 4000)).toEqual(['a']);
  const start = Date.now();
  expect(await firstAnswers([after(5, 'a'), never], 2, 100)).toEqual(['a']);
  expect(Date.now() - start).toBeLessThan(1000);
  expect(await firstAnswers([failing(5)], 1, 1000)).toEqual([]);
  expect(await firstAnswers([], 1, 1000)).toEqual([]);
});

test('"nothing there" needs two relays to say so (#139, #141)', async () => {
  const { readAnswers } = await import('../bunker/src/lib/relayPublish.ts');
  const e = { id: 'a' } as import('nostr-tools').Event;
  expect(readAnswers([], 6)).toBeNull(); // none answered (offline, refused)
  expect(readAnswers([[]], 6)).toBeNull(); // one empty answer: can't say
  expect(readAnswers([[], []], 6)).toEqual([]); // two: nothing there
  expect(readAnswers([[e]], 6)).toEqual([e]); // one that has it: found
  expect(readAnswers([[e], [e]], 6)).toEqual([e]); // deduplicated
  expect(readAnswers([[]], 1)).toEqual([]); // a single relay configured
});
