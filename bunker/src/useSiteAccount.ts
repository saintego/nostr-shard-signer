// Sites with their own clientId (#73 D3, D5, D6; #83): what happens after the
// site's own Web3Auth login. This site login's cache opens (a global account),
// or the site-only account starts (the site login key itself), or the widget
// asks, or it offers "Continue with your global account". Without a site
// session, rule (B) opens the last login's cache for 7 days.
import { createElement, useCallback, useState } from 'react';
import { BringOver } from './components/BringOver';
import { type ChoiceStep, SiteAccountChoice } from './components/SiteAccountChoice';
import { deriveMarkerAddress } from './lib/derive';
import { markerFilter, markerHint } from './lib/marker';
import { queryRelays } from './lib/relayPublish';
import { bringOverGlobally } from './lib/sharedSignIn';
import {
  type DeviceAnswer,
  decideAfterSiteLogin,
  type GlobalLogin,
  type Hint,
  type Intent,
  lastLogin,
  loadAnswer,
  loginHash,
  type Next,
  remember,
  saveAnswer,
  setLastLogin,
} from './lib/siteAccount';
import type { KeyMaterial } from './lib/web3auth';
import type { GlobalTarget } from './useSharedSignIn';

type Profile = { name?: string; picture?: string } | undefined;
type ParentMessage = { type: 'RESIZE'; state: 'modal' | 'button' };

interface Deps {
  parentOrigin: string;
  globalLogin: GlobalLogin;
  /** The global account's side (useSharedSignIn). */
  global: {
    readonly restoreIn: (target: GlobalTarget, siteSignedIn: boolean) => Promise<boolean>;
    readonly continueGlobal: (target: GlobalTarget) => Promise<void>;
  };
  /** The site-only account: the site login is the identity. */
  onSiteOnly: (km: KeyMaterial, profile: Profile) => Promise<void>;
  /** Back to the Sign up / Sign in buttons. */
  onCancel: () => void;
  postToParent: (msg: ParentMessage) => void;
}

/** One site login, waiting for the user's choice. */
interface Pending {
  readonly step: ChoiceStep;
  readonly km: KeyMaterial;
  readonly profile: Profile;
  readonly hash: string;
  readonly address: string;
  readonly hint: Hint;
  readonly answer: DeviceAnswer | null;
  readonly intent: Intent;
}

const hostOf = (origin: string) => {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
};

/** The global account's target for one site login: its cache slot and marker address. */
const targetOf = (p: { hash: string; address: string }): GlobalTarget => ({
  slot: { kind: 'site', loginHash: p.hash },
  markerAddress: p.address,
});

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export function useSiteAccount({
  parentOrigin,
  globalLogin,
  global,
  onSiteOnly,
  onCancel,
  postToParent,
}: Deps) {
  const [pending, setPending] = useState<Pending | null>(null);
  // The site-only account in use, for "Use this account on other sites" (D9).
  const [siteOnly, setSiteOnly] = useState<KeyMaterial | null>(null);

  /** Acts on a decision for this site login. */
  const proceed = useCallback(
    async (next: Next, p: Omit<Pending, 'step'>) => {
      if (next.next === 'cache') return;
      if (next.next === 'site-only') {
        setPending(null);
        saveAnswer(p.hash, remember(p.answer, { kind: 'site' }));
        setSiteOnly(p.km);
        return onSiteOnly(p.km, p.profile);
      }
      const step: ChoiceStep =
        next.next === 'global'
          ? { kind: 'global', noteFound: next.noteFound }
          : { kind: 'ask', question: next.question };
      setPending({ ...p, step });
      postToParent({ type: 'RESIZE', state: 'modal' });
    },
    [onSiteOnly, postToParent]
  );

  /** After the site's own login (a new one, or a session confirmed by a key call). */
  const afterSiteLogin = useCallback(
    async (km: KeyMaterial, profile: Profile, intent: Intent) => {
      const hash = await loginHash(km.publicKeyHex);
      const address = await deriveMarkerAddress(km.privateKeyBytes, parentOrigin);
      if (await global.restoreIn(targetOf({ hash, address }), true)) {
        setLastLogin(hash);
        return;
      }
      const hint = markerHint((await queryRelays(markerFilter(address))) ?? [], address);
      const answer = loadAnswer(hash);
      const next = decideAfterSiteLogin({ intent, globalLogin, hasCache: false, answer, hint });
      await proceed(next, { km, profile, hash, address, hint, answer, intent });
    },
    [parentOrigin, globalLogin, global, proceed]
  );

  /** No site session (expired, C16): the last login's cache, within rule (B)'s window. */
  const restoreWithoutSiteLogin = useCallback(async () => {
    const hash = lastLogin();
    return hash ? global.restoreIn({ slot: { kind: 'site', loginHash: hash } }, false) : false;
  }, [global]);

  const choice = pending
    ? createElement(SiteAccountChoice, {
        step: pending.step,
        site: hostOf(parentOrigin),
        onWantGlobal: () =>
          setPending({ ...pending, step: { kind: 'global', noteFound: pending.hint.found } }),
        onContinueGlobal: () => {
          const p = pending;
          setPending(null);
          // The popup opens in this click; the answer is kept once it succeeds.
          void global
            .continueGlobal(targetOf(p))
            .then(() => saveAnswer(p.hash, remember(p.answer, { kind: 'global' })));
        },
        onSiteOnly: () => {
          const id = pending.hint.found ? pending.hint.eventId : undefined;
          const answer = remember(pending.answer, {
            kind: 'site',
            ...(id ? { confirmed: id } : {}),
          });
          void proceed({ next: 'site-only' }, { ...pending, answer });
        },
        onNotMine: () => {
          if (!pending.hint.found) return;
          const answer = remember(pending.answer, { notMine: pending.hint.eventId });
          saveAnswer(pending.hash, answer);
          const next = decideAfterSiteLogin({
            intent: pending.intent,
            globalLogin,
            hasCache: false,
            answer,
            hint: pending.hint,
          });
          void proceed(next, { ...pending, answer });
        },
        onCancel: () => {
          setPending(null);
          onCancel();
        },
      })
    : null;

  const bringOver =
    siteOnly && globalLogin !== 'off'
      ? createElement(BringOver, {
          site: hostOf(parentOrigin),
          onBringOver: () =>
            bringOverGlobally(parentOrigin, toHex(siteOnly.privateKeyBytes), siteOnly.publicKeyHex),
        })
      : null;

  /** Signed out on this site. */
  const forget = useCallback(() => setSiteOnly(null), []);

  return { afterSiteLogin, restoreWithoutSiteLogin, choice, bringOver, forget };
}
