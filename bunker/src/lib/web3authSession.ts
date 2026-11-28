// Where Web3Auth keeps a session, and how the signer ends one without Web3Auth's
// help (#73 D23, #79; checks C7 and C16 in #75).
//
// Web3Auth keeps a session in three places:
//   - tokens in localStorage: `<sessionKey>:session_id`, `:access_token`, `:id_token`
//     (the session id unlocks Web3Auth's stored session);
//   - the refresh token in a cookie `<sessionKey>:refresh_token` (SameSite=Strict,
//     so a cross-site iframe can't write it);
//   - its state (which connector, whether connected) under `Web3Auth-state`.
// These names are Web3Auth internals; tests/web3authNames.spec.ts fails when they
// change.

/** The names one Web3Auth instance uses. */
export interface SessionNames {
  /** The auth connector's `sessionKey`: the tokens' prefix. */
  readonly sessionKey: string;
  /** Prefix for Web3Auth's state key ('' = Web3Auth's default name). */
  readonly statePrefix: string;
  /** Where the state lives: sessionStorage makes a closed tab forget the session. */
  readonly stateIn: 'local' | 'session';
}

export const WEB3AUTH_STATE_KEY = 'Web3Auth-state';
export const TOKEN_KEYS = ['session_id', 'access_token', 'id_token'] as const;
export const REFRESH_COOKIE = 'refresh_token';

/**
 * The site's own sign-in (an own clientId, or today's shared sign-in): Web3Auth's
 * default names, so sessions from before this change stay signed in.
 */
export const SITE_SESSION: SessionNames = { sessionKey: 'auth_store', statePrefix: '', stateIn: 'local' };

/**
 * The global sign-in (#80): its own names, so ending it never ends the site's
 * session, and its state only for the tab.
 */
export const GLOBAL_SESSION: SessionNames = { sessionKey: 'auth_store_global', statePrefix: 'w3a_global_', stateIn: 'session' };

/** The storage a session can be in (the page's, or a fake in tests). */
export interface SessionEnv {
  readonly local: Pick<Storage, 'getItem' | 'removeItem'>;
  readonly session: Pick<Storage, 'getItem' | 'removeItem'>;
  /** document.cookie (read). */
  readonly cookies: () => string;
  /** Expires a cookie by name. */
  readonly expireCookie: (name: string) => void;
}

const stateStore = (names: SessionNames, env: SessionEnv) => (names.stateIn === 'session' ? env.session : env.local);
const stateKey = (names: SessionNames) => names.statePrefix + WEB3AUTH_STATE_KEY;
const tokenKeys = (names: SessionNames) => TOKEN_KEYS.map((k) => `${names.sessionKey}:${k}`);
const refreshCookie = (names: SessionNames) => `${names.sessionKey}:${REFRESH_COOKIE}`;
const cookieNames = (env: SessionEnv) =>
  env
    .cookies()
    .split(';')
    .map((c) => c.trim().split('=')[0] ?? '')
    .filter(Boolean);

/**
 * What of a session is left in storage, found without starting Web3Auth
 * (so a visitor without one never counts as a Web3Auth user). Token keys and the
 * refresh cookie mean a session that could be restored; the state alone doesn't.
 */
export function findSession(names: SessionNames, env: SessionEnv): string[] {
  const found = tokenKeys(names).filter((k) => env.local.getItem(k) !== null);
  if (cookieNames(env).includes(refreshCookie(names))) found.push(`cookie ${refreshCookie(names)}`);
  return found;
}

/**
 * Deletes a session's tokens, refresh cookie and state directly. Used after
 * Web3Auth's own logout, and instead of it when that fails (code 5113: a
 * session restored on an origin no longer allowlisted can't log out).
 */
export function deleteSession(names: SessionNames, env: SessionEnv): void {
  for (const k of tokenKeys(names)) env.local.removeItem(k);
  if (cookieNames(env).includes(refreshCookie(names))) env.expireCookie(refreshCookie(names));
  stateStore(names, env).removeItem(stateKey(names));
}

/** The page's own storage. */
export const browserSessionEnv = (): SessionEnv => ({
  local: localStorage,
  session: sessionStorage,
  cookies: () => document.cookie,
  expireCookie: (name) => {
    // Web3Auth writes it with Path=/ (CookieStorage's default), through
    // document.cookie; the async Cookie Store API isn't in every browser.
    // biome-ignore lint/suspicious/noDocumentCookie: matches how Web3Auth writes it
    document.cookie = `${name}=; Path=/; Max-Age=0; SameSite=Strict; Secure`;
  },
});

/** Ends a session: Web3Auth's logout if it can, then direct deletion either way. */
export async function endSession(
  logout: (() => Promise<void>) | null,
  names: SessionNames,
  env: SessionEnv = browserSessionEnv(),
): Promise<void> {
  try {
    await logout?.();
  } catch {
    // Not connected (5113) or offline: the keys still go below.
  }
  deleteSession(names, env);
}

/**
 * On every signer popup (and later the signer's tab): a leftover global
 * session, from a popup that closed or crashed during the global sign-in, is
 * ended. `logout`, when given, also ends it on Web3Auth's side.
 */
export async function sweepGlobalSession(
  logout: (() => Promise<void>) | null = null,
  env: SessionEnv = browserSessionEnv(),
): Promise<string[]> {
  const found = findSession(GLOBAL_SESSION, env);
  if (found.length > 0) await endSession(logout, GLOBAL_SESSION, env);
  return found;
}
