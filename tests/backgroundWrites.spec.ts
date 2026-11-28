// Relay writes that don't hold up the sign-in window (#110).
import { expect, test } from '@playwright/test';
import { backgroundWrites } from '../bunker/src/lib/backgroundWrites.ts';

const later = () => {
  let done = () => {};
  const promise = new Promise<void>((r) => {
    done = r;
  });
  return { promise, done };
};

test('a write starts at once, returns before it finishes, and settled() waits for it', async () => {
  const slow = later();
  const sent: number[][] = [];
  const w = backgroundWrites<number>(async (events) => {
    sent.push(events);
    await slow.promise;
  });
  await w.publish([1]);
  expect(sent).toEqual([[1]]);
  expect(w.pending()).toBe(1);
  let settled = false;
  const waiting = w.settled(5000).then(() => {
    settled = true;
  });
  await new Promise((r) => setTimeout(r, 20));
  expect(settled).toBe(false);
  slow.done();
  await waiting;
  expect(w.pending()).toBe(0);
});

test('settled() gives up after maxMs, and a failed write is dropped quietly', async () => {
  const w = backgroundWrites<number>(() => new Promise(() => {}));
  await w.publish([1]);
  const start = Date.now();
  await w.settled(50);
  expect(Date.now() - start).toBeLessThan(1000);
  const failing = backgroundWrites<number>(async () => {
    throw new Error('relay down');
  });
  await failing.publish([2]);
  await failing.settled(1000);
  expect(failing.pending()).toBe(0);
});
