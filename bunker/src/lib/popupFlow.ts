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

/** The login's own account (it's the primary): Welcome back, or a new account. */
export async function openOwn(first: PopupLogin, site: string, deps: FlowDeps): Promise<Step> {
  const root = await deriveRoot(first.login.key);
  const account = await openGlobalAccountFromRoot(root, site, {
    ...deps,
    primary: primaryOf(first),
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
    });
    return { step: 'account', account, profile: first.profile, createdWith: null };
  }
  await found.ownList.close().catch(() => {});
  if (r.kind === 'linked') return openLinked(first, r.root, r.primary, site, deps);
  if (r.kind === 'restricted') return { step: 'restricted', envelope: r.envelope, first };
  if (r.kind === 'both')
    return { step: 'question', kind: 'both', first, root: r.root, primary: r.primary };
  if (r.kind === 'none')
    return { step: 'question', kind: 'none', wasUnlinked: r.wasUnlinked, first };
  return { step: 'question', kind: 'unknown', first };
}
