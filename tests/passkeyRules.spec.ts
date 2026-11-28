// Passkey rules (#73 D17, #89; checks C5, C20).
import { expect, test } from '@playwright/test';
import { type GestureReason, passkeyRules } from '../bunker/src/lib/passkeyRules.ts';

const err = (name: string, message = '') => Object.assign(new Error(message), { name });
const created = { credId: 'c', prfOutput: new Uint8Array(32) };
const result = { credId: 'c', prfOutput: new Uint8Array(32) };

/** A fake setup: `frame` and `popup` behaviours, and a user who clicks every prompt. */
function setup(o: { frameCreate?: () => Promise<unknown>; frameGet?: () => Promise<unknown>; frameMayCreate?: boolean; cancelAfter?: number }) {
  const asked: GestureReason[] = [];
  const calls: string[] = [];
  let opened = 0;
  const rules = passkeyRules({
    frame: {
      rpId: 'signer.test',
      supported: async () => true,
      create: async () => { calls.push('frame.create'); return (await (o.frameCreate ?? (async () => created))()) as typeof created; },
      get: async () => { calls.push('frame.get'); return (await (o.frameGet ?? (async () => result))()) as typeof result; },
    },
    popup: {
      rpId: 'signer.test',
      supported: async () => true,
      create: async () => { calls.push('popup.create'); return created; },
      get: async () => { calls.push('popup.get'); return result; },
    },
    openPopup: () => { opened++; },
    askGesture: async (reason) => {
      asked.push(reason);
      if (o.cancelAfter !== undefined && asked.length > o.cancelAfter) throw new Error('Cancelled');
      rules.onGesture();
    },
    frameMayCreate: o.frameMayCreate,
  });
  return { rules, asked, calls, opened: () => opened };
}

const args = { userId: new Uint8Array(16), userName: 'u', excludeCredIds: [], prfInput: new Uint8Array(32) };

test('create and unlock in the widget, each on its own click', async () => {
  const s = setup({});
  s.rules.onGesture(); // Evolustr's own gesture prompt before the first call
  await s.rules.passkeys.create(args);
  await s.rules.passkeys.get({ allowCredIds: [], prfInput: new Uint8Array(32) });
  expect(s.calls).toEqual(['frame.create', 'frame.get']);
  // The get came right after the create: it asked for a new click (Safari's rule).
  expect(s.asked).toEqual(['retry']);
});

test("Safari's refusal to create in a frame moves creating to the popup, opened from a new click", async () => {
  const s = setup({ frameCreate: async () => { throw err('NotAllowedError', 'The origin of the document is not the same as its ancestors.'); } });
  s.rules.onGesture();
  await s.rules.passkeys.create(args);
  expect(s.calls).toEqual(['frame.create', 'popup.create']);
  expect(s.asked).toEqual(['popup']);
  expect(s.opened()).toBe(1);
  // Later creates go to the popup straight away.
  await s.rules.passkeys.create(args);
  expect(s.calls.slice(2)).toEqual(['popup.create']);
});

test('a refused unlock offers "Try again", then succeeds', async () => {
  let n = 0;
  const s = setup({ frameGet: async () => { if (n++ === 0) throw err('NotAllowedError', 'request is not allowed'); return result; } });
  s.rules.onGesture();
  await s.rules.passkeys.get({ allowCredIds: [], prfInput: new Uint8Array(32) });
  expect(s.calls).toEqual(['frame.get', 'frame.get']);
  expect(s.asked).toEqual(['retry']);
});

test('the user can still cancel; other errors are not retried', async () => {
  const s = setup({ frameGet: async () => { throw err('NotAllowedError'); }, cancelAfter: 0 });
  s.rules.onGesture();
  await expect(s.rules.passkeys.get({ allowCredIds: [], prfInput: new Uint8Array(32) })).rejects.toThrow('Cancelled');
  const t = setup({ frameGet: async () => { throw err('InvalidStateError'); } });
  t.rules.onGesture();
  await expect(t.rules.passkeys.get({ allowCredIds: [], prfInput: new Uint8Array(32) })).rejects.toThrow();
  expect(t.calls).toEqual(['frame.get']);
});

test('when the frame is known not to allow creating, the popup is used from the start', async () => {
  const s = setup({ frameMayCreate: false });
  s.rules.onGesture();
  await s.rules.passkeys.create(args);
  expect(s.calls).toEqual(['popup.create']);
});
