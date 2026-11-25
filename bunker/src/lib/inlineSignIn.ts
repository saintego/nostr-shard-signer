// The global sign-in in the widget itself (#122): Web3Auth's panel in the
// iframe, the account looked up here, and the window only for the screens a
// page mustn't be able to cover (Welcome back, questions, Manage).

import type { GlobalAccount, NewProfile } from './globalAccount';
import type { GlobalAnswer, HandedLogin } from './globalPopup';
import { afterLogin, type FlowDeps, openOwn, type Step } from './popupFlow';
import type { PopupLogin } from './popupLogin';

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export type InlineOutcome =
  /** Done here: the site's grant. */
  | { readonly kind: 'signed-in'; readonly answer: GlobalAnswer }
  /** A new account: its identity 0 is paired; ask about the name and picture, then grant. */
  | {
      readonly kind: 'new-account';
      readonly account: GlobalAccount;
      readonly pubkey: string;
      readonly profile: NewProfile;
    }
  /** No account uses this sign-in yet: create one here, or link it to another in the window. */
  | { readonly kind: 'none'; readonly first: PopupLogin; readonly wasUnlinked: boolean }
  /** The window has to continue, from this login. */
  | { readonly kind: 'window'; readonly login: HandedLogin };

/** The answer for `pubkey` (paired), then the account closed (its writes go on in the background). */
export async function answerFor(
  account: GlobalAccount,
  pubkey: string,
  defer: (work: Promise<unknown>) => void
): Promise<GlobalAnswer> {
  try {
    const grant = await account.grant(pubkey);
    const marker = await account.siteMarker();
    return { grant, ...(marker ? { marker } : {}) };
  } finally {
    defer(account.close());
  }
}

/** The login, as the window takes it (#122). */
export const handOver = (first: PopupLogin): HandedLogin => ({
  key: toHex(first.login.key),
  provider: first.login.provider,
  userId: first.login.userId,
  masked: first.login.masked,
  ...(first.profile?.name ? { name: first.profile.name } : {}),
  ...(first.profile?.picture ? { picture: first.profile.picture } : {}),
});

/** A login the widget handed over, as the window's own (#122). */
export const fromHanded = (l: HandedLogin): PopupLogin => ({
  login: {
    key: Uint8Array.from(l.key.match(/../g) ?? [], (x) => Number.parseInt(x, 16)),
    provider: l.provider,
    userId: l.userId,
    masked: l.masked,
  },
  profile:
    l.name || l.picture
      ? { ...(l.name ? { name: l.name } : {}), ...(l.picture ? { picture: l.picture } : {}) }
      : null,
});

type InlineDeps = FlowDeps & { defer: (work: Promise<unknown>) => void };

/** An account step: a new account's identity 0, identities already paired here, or the window. */
async function fromAccount(
  step: Extract<Step, { step: 'account' }>,
  first: PopupLogin,
  deps: InlineDeps
): Promise<InlineOutcome> {
  const { account } = step;
  const identity0 = account.list[0];
  if (account.isNew && identity0) {
    await account.pair(identity0.pubkey);
    const profile = step.profile;
    // Offered only when identity 0 has no profile yet, on relays that answered (#136).
    if (
      profile &&
      (profile.name || profile.picture) &&
      (await account.profileFree(identity0.pubkey))
    )
      return { kind: 'new-account', account, pubkey: identity0.pubkey, profile };
    return { kind: 'signed-in', answer: await answerFor(account, identity0.pubkey, deps.defer) };
  }
  const pairedHere = account.paired[0];
  if (pairedHere)
    return { kind: 'signed-in', answer: await answerFor(account, pairedHere.pubkey, deps.defer) };
  // Welcome back: every identity and site of the account, in the window (D22).
  deps.defer(account.close());
  return { kind: 'window', login: handOver(first) };
}

/**
 * After the login in the widget: done here, a new account's question, "no
 * account uses this sign-in yet" (asked here), or the window for the rest.
 */
export async function afterInlineLogin(
  first: PopupLogin,
  site: string,
  deps: InlineDeps
): Promise<InlineOutcome> {
  const step = await afterLogin(first, site, deps);
  if (step.step === 'account') return fromAccount(step, first, deps);
  if (step.step === 'question' && step.kind === 'none')
    return { kind: 'none', first, wasUnlinked: step.wasUnlinked };
  return { kind: 'window', login: handOver(first) };
}

/** "Create a new account" after "no account uses this sign-in yet", in the widget. */
export async function createInline(
  first: PopupLogin,
  site: string,
  deps: InlineDeps
): Promise<InlineOutcome> {
  const step = await openOwn(first, site, deps);
  if (step.step !== 'account') return { kind: 'window', login: handOver(first) };
  return fromAccount(step, first, deps);
}
