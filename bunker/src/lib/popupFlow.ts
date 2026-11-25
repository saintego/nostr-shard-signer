// What the global sign-in popup shows after a login (#73 D25, review 8; #98):
// the account (its own, or another account's through an envelope), a
// restricted link's identities, or a question. No JSX: the popup renders it.

import { deriveRoot } from './derive';
import { type EnvelopeBody, type Primary, pointerAddress } from './envelope';
import {
  type AccountDeps,
  type GlobalAccount,
  type NewProfile,
  openGlobalAccountFromRoot,
} from './globalAccount';
import type { GlobalOptions } from './globalPopup';
import { type LinkingDeps, lookUp, resolve } from './linking';
import type { PopupLogin } from './popupLogin';

export type FlowDeps = Omit<AccountDeps, 'primary' | 'viaPointer'> &
  Pick<LinkingDeps, 'openCopies'>;

export type Step =
  | {
      readonly step: 'account';
      readonly account: GlobalAccount;
      readonly profile: NewProfile | null;
      /** Signed in through a link: who created the account ("created with Google (a…@gmail.com)"). */
      readonly createdWith: Primary | null;
    }
  /** Signed in with a sign-in this account unlinked (review 8, item 3). */
  | { readonly step: 'unlinked'; readonly date: string }
  | {
      readonly step: 'restricted';
      readonly envelope: Extract<EnvelopeBody, { scope: 'restricted' }>;
      readonly first: PopupLogin;
    }
  | {
      readonly step: 'question';
      readonly kind: 'none';
      readonly wasUnlinked: boolean;
      readonly first: PopupLogin;
    }
  | { readonly step: 'question'; readonly kind: 'unknown'; readonly first: PopupLogin }
  | {
      readonly step: 'question';
      readonly kind: 'both';
      readonly first: PopupLogin;
      readonly root: Uint8Array;
      readonly primary: Primary;
    };

const primaryOf = (p: PopupLogin): Primary => ({
  provider: p.login.provider,
  masked: p.login.masked,
});

/**
 * The login's own account (it's the primary): Welcome back, or a new account.
 * `known`: what the lookup proved (#136): it found the account, or it answered
 * in full and found nothing ("Create a new account" after "none").
 */
export async function openOwn(
  first: PopupLogin,
  site: string,
  deps: FlowDeps,
  known?: 'existing' | 'none'
): Promise<Step> {
  const root = await deriveRoot(first.login.key);
  const account = await openGlobalAccountFromRoot(root, site, {
    ...deps,
    primary: primaryOf(first),
    knownExisting: known === 'existing',
    provenNew: known === 'none',
  });
  return { step: 'account', account, profile: first.profile, createdWith: null };
}

/** Another account, through this login's envelope. */
export async function openLinked(
  first: PopupLogin,
  root: Uint8Array,
  primary: Primary,
  site: string,
  deps: FlowDeps
): Promise<Step> {
  const { pubkey } = await pointerAddress(first.login.key);
  const account = await openGlobalAccountFromRoot(root, site, {
    ...deps,
    primary,
    viaPointer: pubkey,
  });
  if (account.unlinkedVia) {
    const date = account.unlinkedVia;
    await account.close();
    return { step: 'unlinked', date };
  }
  return { step: 'account', account, profile: first.profile, createdWith: primary };
}

/** After a login: look it up and decide (resolve in linking.ts). */
export async function afterLogin(first: PopupLogin, site: string, deps: FlowDeps): Promise<Step> {
  const found = await lookUp(first.login.key, { ...deps, openList: deps.openList });
  const r = resolve(found);
  if (r.kind === 'own') {
    const root = await deriveRoot(first.login.key);
    const account = await openGlobalAccountFromRoot(root, site, {
      ...deps,
      openList: async () => found.ownList,
      primary: primaryOf(first),
      knownExisting: found.own, // #136
    });
    return { step: 'account', account, profile: first.profile, createdWith: null };
  }
  await found.ownList.close(0).catch(() => {}); // only read here
  if (r.kind === 'linked') return openLinked(first, r.root, r.primary, site, deps);
  if (r.kind === 'restricted') return { step: 'restricted', envelope: r.envelope, first };
  if (r.kind === 'both')
    return { step: 'question', kind: 'both', first, root: r.root, primary: r.primary };
  if (r.kind === 'none')
    return { step: 'question', kind: 'none', wasUnlinked: r.wasUnlinked, first };
  return { step: 'question', kind: 'unknown', first };
}

/** What the window does with an account step (#109, #137, D8, D9). */
export type AccountNext =
  | { readonly kind: 'bring-over'; readonly siteKey: string }
  | { readonly kind: 'new'; readonly pubkey: string }
  | { readonly kind: 'finish'; readonly pubkey: string }
  /** Pair it first, then finish: identity 0 of an account that never had another (#136). */
  | { readonly kind: 'pair'; readonly pubkey: string }
  | { readonly kind: 'show' };

export function accountNext(
  account: Pick<GlobalAccount, 'isNew' | 'list' | 'paired' | 'onlyIdentity0'>,
  options: Pick<GlobalOptions, 'intent' | 'siteKey' | 'active'>
): AccountNext {
  const { intent, siteKey } = options;
  // "Use this account on other sites" (D9): stored, then a backup or a skip (#137).
  if (intent === 'bring-over' && siteKey) return { kind: 'bring-over', siteKey };
  // A new account: identity 0, straight away (D8: Welcome back only for an existing account).
  const first = account.list[0];
  if (account.isNew && first && intent !== 'backup') return { kind: 'new', pubkey: first.pubkey };
  // Signing in again where identities are already in use: no Welcome back, no
  // extra click (#109). "Add or manage identities" (it sends `active`) and
  // backup still show it.
  const asked = intent === 'backup' || intent === 'manage' || !!options.active;
  const pairedHere = account.paired[0];
  if (pairedHere && !asked) return { kind: 'finish', pubkey: pairedHere.pubkey };
  // The list is gone but the account only ever had identity 0: nothing to choose (#136).
  if (account.onlyIdentity0 && first && !asked) return { kind: 'pair', pubkey: first.pubkey };
  return { kind: 'show' };
}
