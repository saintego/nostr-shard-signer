// Passkey rules from the checks (#73 D17, #89; C5 and C20 in #75):
//   - unlock (get) in the widget: works in every browser tested;
//   - create in the widget where the browser allows it; Safari refuses it in a
//     cross-site frame ("…not the same as its ancestors"), so then in the
//     signer's popup, opened from a new click;
//   - one WebAuthn call per click: a call without a fresh click asks for one;
//   - NotAllowedError (refused, or the user dismissed the sheet) → "Try again",
//     never a dead end; the user can still cancel.

import type { Passkeys } from '../vendor/evolustr/evolustr.js';

/** Why the widget asks for a click before a passkey step. */
export type GestureReason = 'retry' | 'popup';

export interface PasskeyRulesDeps {
  /** WebAuthn in this frame. */
  readonly frame: Passkeys;
  /** WebAuthn in the signer's popup (opened by `openPopup`). */
  readonly popup: Passkeys;
  /** Opens the popup; called synchronously in a click. */
  readonly openPopup: () => void;
  /**
   * Asks the user for a click (a prompt in the widget); resolves when they
   * click, rejects when they cancel. The click calls `onGesture` first.
   */
  readonly askGesture: (reason: GestureReason) => Promise<void>;
  /**
   * What the browser's permissions policy says about creating in this frame:
   * false = known not allowed (Chromium without the bridge's `allow`), true or
   * undefined = try it.
   */
  readonly frameMayCreate?: boolean;
  /** How many "Try again" rounds before giving up. */
  readonly maxRetries?: number;
}

export interface PasskeyRules {
  readonly passkeys: Passkeys;
  /** Call synchronously from the click that resolves a gesture prompt. */
  readonly onGesture: () => void;
}

const isNotAllowed = (e: unknown) => (e as { name?: string })?.name === 'NotAllowedError';
/** Safari's refusal to create a passkey in a cross-site frame. */
const isFrameRefusal = (e: unknown) => isNotAllowed(e) && /ancestors/i.test((e as Error)?.message ?? '');

export function passkeyRules(deps: PasskeyRulesDeps): PasskeyRules {
  const maxRetries = deps.maxRetries ?? 2;
  // A click the next WebAuthn call may use; each call uses it up.
  let armed = false;
  // The next click opens the popup (a create that must run there).
  let popupNext = false;
  let createInPopup = deps.frameMayCreate === false;

  const onGesture = () => {
    armed = true;
    if (popupNext) deps.openPopup();
  };

  /** Runs one WebAuthn call on a fresh click, asking for one if needed. */
  const withClick = async <T>(reason: GestureReason, call: () => Promise<T>): Promise<T> => {
    if (!armed) await deps.askGesture(reason);
    armed = false;
    return call();
  };

  const withRetries = async <T>(run: () => Promise<T>): Promise<T> => {
    for (let attempt = 0; ; attempt++) {
      try {
        return await run();
      } catch (e) {
        if (!isNotAllowed(e) || isFrameRefusal(e) || attempt >= maxRetries) throw e;
        armed = false; // the next try needs its own click
      }
    }
  };

  const createInPopupNow: Passkeys['create'] = async (args) => {
    popupNext = true;
    try {
      return await withClick('popup', () => deps.popup.create(args));
    } finally {
      popupNext = false;
    }
  };

  const passkeys: Passkeys = {
    rpId: deps.frame.rpId,
    supported: deps.frame.supported,
    create: async (args) => {
      if (createInPopup) return createInPopupNow(args);
      try {
        return await withRetries(() => withClick('retry', () => deps.frame.create(args)));
      } catch (e) {
        if (!isFrameRefusal(e)) throw e;
        createInPopup = true; // Safari: for the rest of this page's life
        return createInPopupNow(args);
      }
    },
    get: (args) => withRetries(() => withClick('retry', () => deps.frame.get(args))),
  };
  return { passkeys, onGesture };
}
