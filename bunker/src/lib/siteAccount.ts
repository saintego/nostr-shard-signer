// Sign up and Sign in on sites with their own clientId (#73 D3, D5, D6; #83).
// After the site's own Web3Auth login, the widget decides between this site's
// cache (a global account), the site-only account (the site login key itself),
// a question, or "Continue with your global account". Pure: the caller reads
// the device's answers, the cache and the marker hint, and acts on the result.

/** `globalLogin` (D3): what a site with its own clientId offers. */
export type GlobalLogin = 'offer' | 'off' | 'require';

export const parseGlobalLogin = (value: string | null): GlobalLogin =>
  value === 'off' || value === 'require' ? value : 'offer';

/** Which button the user pressed. Sign in never creates an account (D5). */
export type Intent = 'sign-up' | 'sign-in';

/** What this device remembers for one site login (keyed by a hash of its pubkey, D5). */
export interface DeviceAnswer {
  /** The account kind chosen for this login; absent until the user chose one. */
  readonly kind?: 'site' | 'global';
  /** Marker events the user called "not mine" on this device. */
  readonly notMine: readonly string[];
  /** Marker events the user already confirmed "only for this site" against. */
  readonly confirmed: readonly string[];
}

/** A note at this site login's marker address (D7), as seen without the root. */
export type Hint = { readonly found: false } | { readonly found: true; readonly eventId: string };

export type Question =
  /** Sign in, nothing found: "Reuse your global account, or start a new account only for this site?" */
  | 'reuse-or-site'
  /** Sign up: "An account only for this site" (default) or "Use my global account". */
  | 'sign-up-choice'
  /** Sign up found a note: "A note was found that you may already have an account here". */
  | 'note-found'
  /** The device said "only for this site", and a new note appeared (asked once per note). */
  | 'note-again';

export type Next =
  /** This site's cache opens: the global account, no global sign-in. */
  | { readonly next: 'cache' }
  /** The site-only account: the site login key is the identity. */
  | { readonly next: 'site-only' }
  /** "Continue with your global account" (opens the signer's popup from a click). */
  | { readonly next: 'global'; readonly noteFound: boolean }
  | { readonly next: 'ask'; readonly question: Question };

export interface SiteState {
  readonly intent: Intent;
  readonly globalLogin: GlobalLogin;
  /** This site login has a cache on this device. */
  readonly hasCache: boolean;
  readonly answer: DeviceAnswer | null;
  readonly hint: Hint;
}

/** A note the user hasn't dismissed or already answered for. */
const freshHint = (hint: Hint, answer: DeviceAnswer | null) =>
  hint.found &&
  !answer?.notMine.includes(hint.eventId) &&
  !answer?.confirmed.includes(hint.eventId);

/** What happens after the site's own login (D5). */
export function decideAfterSiteLogin(s: SiteState): Next {
  if (s.hasCache) return { next: 'cache' };
  if (s.globalLogin === 'require') return { next: 'global', noteFound: s.hint.found };
  const fresh = freshHint(s.hint, s.answer);
  if (s.answer?.kind === 'global') return { next: 'global', noteFound: s.hint.found };
  if (s.answer?.kind === 'site')
    return fresh ? { next: 'ask', question: 'note-again' } : { next: 'site-only' };
  // Nothing remembered on this device.
  if (s.intent === 'sign-in') {
    if (fresh) return { next: 'global', noteFound: true };
    return s.globalLogin === 'off'
      ? { next: 'site-only' }
      : { next: 'ask', question: 'reuse-or-site' };
  }
  if (fresh) return { next: 'ask', question: 'note-found' };
  return s.globalLogin === 'off'
    ? { next: 'site-only' }
    : { next: 'ask', question: 'sign-up-choice' };
}

/** The user's answer, remembered for this site login (D5). */
export function remember(
  answer: DeviceAnswer | null,
  change: {
    readonly kind?: DeviceAnswer['kind'];
    readonly notMine?: string;
    readonly confirmed?: string;
  }
): DeviceAnswer {
  const add = (list: readonly string[], id?: string) =>
    id && !list.includes(id) ? [...list, id] : list;
  const kind = change.kind ?? answer?.kind;
  return {
    ...(kind ? { kind } : {}),
    notMine: add(answer?.notMine ?? [], change.notMine),
    confirmed: add(answer?.confirmed ?? [], change.confirmed),
  };
}

/** Rule (B) (#73, after C16): the device secret alone opens a site's cache this long after the last site sign-in. */
export const SITE_SIGN_IN_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

/** Whether the device secret alone may still open the cache (B). */
export const withinWindow = (lastSiteSignIn: number, now: number) =>
  now - lastSiteSignIn <= SITE_SIGN_IN_WINDOW_MS && lastSiteSignIn <= now + 60_000;

/** The key this device files a site login's answers and cache under: a hash of its pubkey. */
export async function loginHash(pubkeyHex: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`nostr-shard-signer/v1/login|${pubkeyHex}`)
  );
  return Array.from(new Uint8Array(digest).slice(0, 16), (x) =>
    x.toString(16).padStart(2, '0')
  ).join('');
}

// ── This device's answers (iframe storage, partitioned per site) ─────────────

const answerKey = (hash: string) => `nss_site_answer:${hash}`;
const LAST_LOGIN_KEY = 'nss_site_last_login';

const isList = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === 'string');

export function loadAnswer(hash: string): DeviceAnswer | null {
  try {
    const v = JSON.parse(
      localStorage.getItem(answerKey(hash)) ?? 'null'
    ) as Partial<DeviceAnswer> | null;
    if (!v || !isList(v.notMine) || !isList(v.confirmed)) return null;
    const kind = v.kind === 'site' || v.kind === 'global' ? v.kind : undefined;
    return { ...(kind ? { kind } : {}), notMine: v.notMine, confirmed: v.confirmed };
  } catch {
    return null;
  }
}

export function saveAnswer(hash: string, answer: DeviceAnswer): void {
  try {
    localStorage.setItem(answerKey(hash), JSON.stringify(answer));
  } catch {
    // storage blocked: the question comes again
  }
}

/** The site login that last signed in here, so its cache can open without it (B). */
export function lastLogin(): string | null {
  try {
    const v = localStorage.getItem(LAST_LOGIN_KEY);
    return v && /^[0-9a-f]{32}$/.test(v) ? v : null;
  } catch {
    return null;
  }
}

export function setLastLogin(hash: string | null): void {
  try {
    if (hash) localStorage.setItem(LAST_LOGIN_KEY, hash);
    else localStorage.removeItem(LAST_LOGIN_KEY);
  } catch {
    // storage blocked
  }
}
