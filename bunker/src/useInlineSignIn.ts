// The global sign-in in the widget itself (#122): Web3Auth's panel in the
// iframe, the account looked up here, and the sign-in window only for what a
// page mustn't be able to cover. Used by useSharedSignIn.
import type { Web3Auth } from '@web3auth/modal';
import type { Event } from 'nostr-tools';
import { createElement, useCallback, useRef, useState } from 'react';
import {
  InlineContinue,
  InlineNoAccount,
  InlineSheet,
  SheetHeight,
} from './components/InlineSignInViews';
import { NewAccountView } from './components/NewAccountView';
import { backgroundWrites, timed, withTimeout } from './lib/backgroundWrites';
import { flowDeps } from './lib/flowDeps';
import type { HandedLogin } from './lib/globalPopup';
import {
  afterInlineLogin,
  answerFor,
  createInline,
  handOver,
  type InlineOutcome,
} from './lib/inlineSignIn';
import { loginOnce, prepareInstance } from './lib/popupLogin';
import { publishToSignerRelays } from './lib/relayPublish';
import { assertSharedSignInAllowed } from './lib/sharedCanary';
import { keepAnswer, type SharedSession, signInGlobally } from './lib/sharedSignIn';
import type { CacheSlot } from './lib/siteCache';

/** Relay and Evolu writes of the widget's sign-ins: the iframe stays, so they just run. */
const writes = backgroundWrites<Event>(publishToSignerRelays);
/** Where the widget's sign-in reads and writes (the same as the window's). */
// In the site's frame: only what this site needs of the account (#138).
const inlineDeps = () => ({ ...flowDeps(writes), defer: writes.track, scope: 'site' as const });
/** The most the lookup may take before the widget says so (#110). */
const STEP_MAX_MS = 25000;

type ParentMessage = { type: 'RESIZE'; state: 'modal' | 'button'; height?: number };

interface Deps {
  site: string;
  slot: () => CacheSlot;
  setView: (view: 'login' | 'connecting' | 'signing-in') => void;
  postToParent: (msg: ParentMessage) => void;
  onSession: (s: SharedSession) => Promise<void>;
  onFailed: (e: unknown) => void;
  onCancel: () => void;
}

const host = (origin: string) => {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
};

/** Closed without signing in: not an error. */
const cancelled = (e: unknown) =>
  /cancel|closed by the user|5114/i.test((e as Error)?.message ?? String(e));

export function useInlineSignIn({
  site,
  slot,
  setView,
  postToParent,
  onSession,
  onFailed,
  onCancel,
}: Deps) {
  const [step, setStep] = useState<InlineOutcome | null>(null);
  const [busy, setBusy] = useState(false);
  // The instance whose panel is open, so "Nostr signer or bunker" can close it.
  const instanceRef = useRef<Web3Auth | null>(null);

  /** Shows an outcome: signed in, or a step of the widget's sheet. */
  const settle = useCallback(
    async (outcome: InlineOutcome) => {
      if (outcome.kind === 'signed-in') {
        setStep(null);
        return onSession(await keepAnswer(outcome.answer, slot()));
      }
      setStep(outcome);
      setView('login');
      postToParent({ type: 'RESIZE', state: 'modal' });
    },
    [onSession, slot, setView, postToParent]
  );

  /** "Continue with Google, X, Facebook and more": Web3Auth's panel here, then the account. */
  const start = useCallback(async () => {
    // The button-sized spinner while Web3Auth loads; the panel view only once
    // it's ready (an empty full-size panel flickered there before, #128).
    setView('signing-in');
    postToParent({ type: 'RESIZE', state: 'button' });
    try {
      await assertSharedSignInAllowed(); // the canary (#91)
      const instance = await prepareInstance(document.documentElement.lang);
      instanceRef.current = instance;
      setView('connecting');
      postToParent({ type: 'RESIZE', state: 'modal' });
      const first = await timed('provider login', loginOnce(instance, 'panel')).finally(() => {
        // Closed whatever happened: left open, the emptied panel fell over the
        // widget and hid the next step or the error (#123).
        instance.loginModal?.closeModal();
        instanceRef.current = null;
      });
      setView('signing-in');
      postToParent({ type: 'RESIZE', state: 'button' });
      const outcome = await timed(
        'account lookup',
        withTimeout(
          afterInlineLogin(first, site, inlineDeps()),
          STEP_MAX_MS,
          'Checking your account took too long'
        )
      );
      if (outcome.kind !== 'none') first.login.key.fill(0);
      await settle(outcome);
    } catch (e) {
      if (cancelled(e)) return onCancel();
      onFailed(e);
    }
  }, [site, settle, setView, postToParent, onCancel, onFailed]);

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    try {
      await work();
    } catch (e) {
      setStep(null);
      onFailed(e);
    } finally {
      setBusy(false);
    }
  };

  /** Hands the login to the sign-in window (from the click) and takes its answer. */
  const toWindow = (login: HandedLogin) => {
    const pending = signInGlobally(site, { login }, slot());
    setStep(null);
    setView('signing-in');
    postToParent({ type: 'RESIZE', state: 'button' });
    void pending.then(onSession).catch(onFailed);
  };

  const cancel = () => {
    if (step?.kind === 'new-account') writes.track(step.account.close());
    if (step?.kind === 'none') step.first.login.key.fill(0);
    setStep(null);
    onCancel();
  };

  let view = null;
  if (step?.kind === 'none') {
    const s = step;
    view = createElement(InlineNoAccount, {
      provider: s.first.login.provider,
      wasUnlinked: s.wasUnlinked,
      busy,
      onCreate: () =>
        void run(async () => {
          const outcome = await createInline(s.first, site, inlineDeps());
          s.first.login.key.fill(0);
          await settle(outcome);
        }),
      onOther: () => {
        const login = handOver(s.first);
        s.first.login.key.fill(0);
        setStep({ kind: 'window', login });
      },
      onCancel: cancel,
    });
  } else if (step?.kind === 'window') {
    const s = step;
    view = createElement(InlineContinue, {
      site: host(site),
      onContinue: () => toWindow(s.login),
      onCancel: cancel,
    });
  } else if (step?.kind === 'new-account') {
    const s = step;
    view = createElement(
      InlineSheet,
      null,
      createElement(NewAccountView, {
        profile: s.profile,
        busy,
        onContinue: (useProfile: boolean) =>
          void run(async () => {
            if (useProfile) await s.account.publishProfile(s.pubkey, s.profile);
            await settle({
              kind: 'signed-in',
              answer: await answerFor(s.account, s.pubkey, writes.track),
            });
          }),
      })
    );
  }

  /** The page's Nostr signer was picked under the panel: close it (connect() then rejects). */
  const closePanel = () => instanceRef.current?.loginModal?.closeModal();

  // The widget fits its card (#125): the page sizes the iframe to it.
  const fit = useCallback(
    (height: number) => postToParent({ type: 'RESIZE', state: 'modal', height }),
    [postToParent]
  );
  const fitted = view && createElement(SheetHeight.Provider, { value: fit }, view);

  return { start, view: fitted, closePanel };
}
