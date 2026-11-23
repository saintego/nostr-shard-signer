// One provider login in the global sign-in popup (#80, #98): Web3Auth's
// window from the user's click, the key and who signed in, then the global
// session ends at once (#73 D23). The popup keeps an instance ready before
// each click, so the provider's window opens from it.

import type { Web3Auth } from '@web3auth/modal';
import { maskIdentifier } from './envelope';
import type { NewProfile } from './globalAccount';
import type { Login } from './linking';
import { SHARED_SIGN_IN_CLIENT_ID, SHARED_SIGN_IN_NETWORK } from './shared';
import { extractKey, initWeb3Auth, loginWith } from './web3auth';
import { endSession, GLOBAL_SESSION, sweepGlobalSession } from './web3authSession';

/** Web3Auth's names for Google, Apple, Facebook and X. */
export type Provider = 'google' | 'apple' | 'facebook' | 'twitter';

/** The sign-ins the window offers, in this order (#106). */
export const PROVIDERS: readonly Provider[] = ['google', 'apple', 'facebook', 'twitter'];

/** Web3Auth's user info, the fields read here. */
interface UserInfo {
  readonly email?: string;
  readonly name?: string;
  readonly profileImage?: string;
  readonly verifierId?: string;
  readonly userId?: string;
}

/** A fresh instance for the next click: a leftover global session swept first (#79). */
export const prepareInstance = (): Promise<Web3Auth> =>
  sweepGlobalSession().then(() =>
    initWeb3Auth(SHARED_SIGN_IN_CLIENT_ID, GLOBAL_SESSION, SHARED_SIGN_IN_NETWORK)
  );

/** The sign-in account's name and picture, offered for new identities (D15). */
export const profileOf = (info: UserInfo | null): NewProfile | null =>
  info ? { name: info.name || undefined, picture: info.profileImage || undefined } : null;

export interface PopupLogin {
  readonly login: Login;
  readonly profile: NewProfile | null;
}

/**
 * Signs in with `provider` on a prepared instance, then ends the global session
 * whatever happens. The login key stays in this window's memory.
 */
export async function loginOnce(instance: Web3Auth, provider: Provider): Promise<PopupLogin> {
  try {
    await loginWith(instance, provider);
    const km = await extractKey(instance);
    const info = (await instance.getUserInfo().catch(() => null)) as UserInfo | null;
    return {
      login: {
        key: km.privateKeyBytes,
        provider,
        userId: info?.verifierId ?? info?.userId ?? info?.email ?? '',
        masked: maskIdentifier(info?.email || info?.name || ''),
      },
      profile: profileOf(info),
    };
  } finally {
    await endSession(() => instance.logout(), GLOBAL_SESSION);
  }
}
