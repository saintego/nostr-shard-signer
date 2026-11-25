// The global sign-in in the signer's popup (#73 D5, D6, D22; #80).
//
// The widget (the signer's iframe on a site) opens this popup from the user's
// click, unnamed ('_blank', #77). The popup runs the global Web3Auth sign-in on
// the signer's own top-level storage, derives what this site needs, sends it to
// the widget with postMessage, deletes the global session and closes.
//
// What crosses (#73 update 2):
//   widget → popup: the site's origin (the popup checks it against the widget's
//                   own address where the browser shows it);
//   popup → widget: the site's store key and the keys of the identities paired
//                   with it, and the active one (siteGrant.ts); the widget
//                   seals them with its device secret.
// Never from the popup: the login key or the root; they stay in its memory.
// The other way, the widget may hand over a login it already made (#122,
// HandedLogin, its key included), so the user doesn't sign in twice. Since
// #122 the sign-in itself can run in the widget, inside the site's page: the
// root and the account are then briefly in the widget's memory (#138).

import type { BackupMethod } from './backup';
import { openerDocument, sameOpenerDocument } from './openerGuard';
import { parseSiteGrant, type SiteGrant } from './siteGrant';

export const GLOBAL_PARAM = 'global-signin';

/**
 * A login the widget already made (#122), handed to the window so the user
 * doesn't sign in twice. Only between the signer's own widget and window.
 */
export interface HandedLogin {
  /** The login key, hex. */
  readonly key: string;
  readonly provider: string;
  readonly userId: string;
  readonly masked: string;
  readonly name?: string;
  readonly picture?: string;
}

export interface GlobalRequest {
  readonly type: 'NSS_GLOBAL_REQUEST';
  /** The site's origin, as the widget verified it (its parent). */
  readonly site: string;
  /** What the user asked for in the widget: sign in (default) or back up (#87). */
  readonly intent?: GlobalIntent;
  /** The identity the widget uses now, to keep it active after a backup. */
  readonly active?: string;
  /** The page chose the signer's own provider buttons over Web3Auth's panel (#113). */
  readonly ui?: 'buttons';
  /** A login the widget made; the window continues from it (#122). */
  readonly login?: HandedLogin;
  /** Own-clientId sites: this site login's marker address (D7), derived in the iframe. */
  readonly markerAddress?: string;
  /**
   * "Use this account on other sites" (D9): the site-only account's key, sent
   * only with that intent, from the user's click; it becomes a stored identity.
   */
  readonly siteKey?: string;
  /** The widget's random nonce; the answer must carry it back (#144). */
  readonly nonce?: string;
}

/** What the widget asked for; 'manage': "Add or manage identities", the window opens at Manage (#129). */
export type GlobalIntent = 'sign-in' | 'backup' | 'bring-over' | 'manage';

/** What the widget may pass along (choices, not data the popup trusts). */
export interface GlobalOptions {
  readonly intent?: GlobalIntent;
  readonly active?: string;
  /** The signer's own provider buttons instead of Web3Auth's panel (#113). */
  readonly ui?: 'buttons';
  /** A login the widget made; the window continues from it (#122). */
  readonly login?: HandedLogin;
  /** Own-clientId sites: the marker's `d` tag (the site login key itself only with 'bring-over'). */
  readonly markerAddress?: string;
  /** 'bring-over' only: the site-only account's key (D9). */
  readonly siteKey?: string;
}

/** What the widget gets back. */
export interface GlobalAnswer {
  readonly grant: SiteGrant;
  /** The user saved a backup in the popup, and how (#37, #87). */
  readonly backedUp?: BackupMethod;
  /** Own-clientId sites: this site's signed marker (JSON), to keep and re-send (D7). */
  readonly marker?: string;
}

export interface GlobalResult {
  readonly type: 'NSS_GLOBAL_RESULT';
  /** The request's nonce (#144). */
  readonly nonce?: string;
  readonly grant?: SiteGrant;
  readonly backedUp?: BackupMethod;
  readonly marker?: string;
  readonly error?: string;
}

const READY = 'NSS_GLOBAL_READY';

// ── In the widget ─────────────────────────────────────────────────────────────

/**
 * Opens the popup; call it synchronously from the user's click. Returns the
 * window (null if the browser blocked it).
 */
export function openGlobalPopup(): Window | null {
  const url = new URL(location.href);
  const locale = url.searchParams.get('locale');
  url.search = `?${GLOBAL_PARAM}=1`;
  if (locale) url.searchParams.set('locale', locale);
  url.hash = '';
  return window.open(url.toString(), '_blank', 'popup,width=440,height=640');
}

/** The popup's answer, checked field by field. */
function parseResult(d: Partial<Omit<GlobalResult, 'type'>>): GlobalAnswer | Error {
  if (typeof d.error === 'string') return new Error(d.error);
  const grant = parseSiteGrant(d.grant);
  if (!grant) return new Error('The sign-in window sent an invalid answer');
  const backedUp = d.backedUp === 'nsec' || d.backedUp === 'ncryptsec' ? d.backedUp : undefined;
  const marker = typeof d.marker === 'string' && d.marker.length < 4096 ? d.marker : undefined;
  return { grant, ...(backedUp ? { backedUp } : {}), ...(marker ? { marker } : {}) };
}

/**
 * Talks to the popup: sends the site once it says it's ready, resolves with its
 * result. Rejects when the popup closes without one.
 */
export function awaitGlobalResult(
  popup: Window,
  site: string,
  options: GlobalOptions = {}
): Promise<GlobalAnswer> {
  // Only the answer to this request counts, not one meant for an earlier widget (#144).
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, '0')
  ).join('');
  return new Promise((resolve, reject) => {
    const done = () => {
      clearInterval(closedPoll);
      window.removeEventListener('message', listener);
    };
    const listener = (e: MessageEvent) => {
      if (e.source !== popup || e.origin !== location.origin) return;
      const d = e.data as Partial<Omit<GlobalResult, 'type'>> & { type?: string };
      if (d?.type === READY) {
        const request: GlobalRequest = { type: 'NSS_GLOBAL_REQUEST', site, ...options, nonce };
        popup.postMessage(request, location.origin);
        return;
      }
      if (d?.type !== 'NSS_GLOBAL_RESULT' || d.nonce !== nonce) return;
      done();
      const result = parseResult(d);
      if (result instanceof Error) reject(result);
      else resolve(result);
    };
    // Closed without a result: seen twice in a row, so a result posted just
    // before the popup closed itself still arrives.
    let closedSeen = 0;
    const closedPoll = setInterval(() => {
      closedSeen = popup.closed ? closedSeen + 1 : 0;
      if (closedSeen < 2) return;
      done();
      reject(new Error('The sign-in window was closed'));
    }, 500);
    window.addEventListener('message', listener);
  });
}

// ── In the popup ──────────────────────────────────────────────────────────────

/** The checks the popup makes on its opener before serving it. */
export interface OpenerCheck {
  readonly ok: boolean;
  readonly reason?: string;
}

/**
 * The popup serves only the signer's own widget: same origin, the signer page
 * (not another page on this origin), inside a frame, and, where the browser
 * tells us the frame's parent, on the site it asks for. Before #60 the signer
 * shares its origin with other pages; this keeps those from using the popup.
 */
export function checkOpener(opener: Window | null, site: string, signerPath: string): OpenerCheck {
  if (!opener) return { ok: false, reason: 'no opener' };
  let path: string;
  let isFrame: boolean;
  let ancestors: DOMStringList | undefined;
  try {
    // Same origin only: reading these throws for another origin.
    path = opener.location.pathname;
    isFrame = opener !== opener.top;
    ancestors = opener.location.ancestorOrigins;
  } catch {
    return { ok: false, reason: 'opener on another origin' };
  }
  if (path !== signerPath) return { ok: false, reason: 'opener is not the signer' };
  if (!isFrame) return { ok: false, reason: 'opener is not embedded in a site' };
  if (ancestors && ancestors.length > 0 && ancestors[0] !== site)
    return { ok: false, reason: 'the site does not match the widget' };
  try {
    if (new URL(site).origin !== site) return { ok: false, reason: 'not an origin' };
  } catch {
    return { ok: false, reason: 'not an origin' };
  }
  return { ok: true };
}

const isHex64 = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const text = (s: unknown, max: number): s is string => typeof s === 'string' && s.length <= max;

/** A handed login, checked field by field (#122); null if anything is off. */
export function parseHandedLogin(d: unknown): HandedLogin | null {
  const l = d as Partial<Record<keyof HandedLogin, unknown>> | null;
  if (!l || !isHex64(l.key) || typeof l.provider !== 'string' || !/^[a-z_]{1,40}$/.test(l.provider))
    return null;
  if (!text(l.userId, 300) || !text(l.masked, 300)) return null;
  if (l.name !== undefined && !text(l.name, 300)) return null;
  if (l.picture !== undefined && !(text(l.picture, 2000) && /^https:\/\//.test(l.picture)))
    return null;
  return {
    key: l.key,
    provider: l.provider,
    userId: l.userId,
    masked: l.masked,
    ...(l.name !== undefined ? { name: l.name } : {}),
    ...(l.picture !== undefined ? { picture: l.picture } : {}),
  };
}

/** The widget's choices, checked field by field (anything else is dropped). */
export function parseOptions(d: Partial<GlobalRequest>): GlobalOptions {
  return {
    ...(d.intent === 'backup' || d.intent === 'bring-over' || d.intent === 'manage'
      ? { intent: d.intent }
      : {}),
    ...(isHex64(d.active) ? { active: d.active } : {}),
    ...(d.ui === 'buttons' ? { ui: 'buttons' as const } : {}),
    ...(parseHandedLogin(d.login) ? { login: parseHandedLogin(d.login) as HandedLogin } : {}),
    ...(isHex64(d.markerAddress) ? { markerAddress: d.markerAddress } : {}),
    ...(d.intent === 'bring-over' && isHex64(d.siteKey) ? { siteKey: d.siteKey } : {}),
  };
}

/**
 * Wires the popup page: tells the opener it's ready, and calls `onRequest`
 * with the site once the opener asks and passes `checkOpener`.
 */
export function serveGlobalPopup(
  signerPath: string,
  onRequest: (
    site: string,
    /** False when nothing was sent: the widget's frame changed since it asked (#144). */
    reply: (result: Omit<GlobalResult, 'type' | 'nonce'>) => boolean,
    options: GlobalOptions
  ) => void,
  onRefused: (reason: string) => void
): () => void {
  const opener = window.opener as Window | null;
  if (!opener) {
    onRefused('no opener');
    return () => {};
  }
  const listener = (e: MessageEvent) => {
    if (e.source !== opener || e.origin !== location.origin) return;
    const d = e.data as Partial<GlobalRequest>;
    if (d?.type !== 'NSS_GLOBAL_REQUEST' || typeof d.site !== 'string') return;
    window.removeEventListener('message', listener);
    const check = checkOpener(opener, d.site, signerPath);
    if (!check.ok) return onRefused(check.reason ?? 'refused');
    const site = d.site;
    const asked = openerDocument(opener);
    const nonce = typeof d.nonce === 'string' ? d.nonce.slice(0, 64) : undefined;
    onRequest(
      site,
      (result) => {
        // The site may have navigated its frame meanwhile: check it again (#144).
        if (!checkOpener(opener, site, signerPath).ok || !sameOpenerDocument(opener, asked))
          return false;
        opener.postMessage(
          { type: 'NSS_GLOBAL_RESULT', ...result, ...(nonce ? { nonce } : {}) },
          location.origin
        );
        return true;
      },
      parseOptions(d)
    );
  };
  window.addEventListener('message', listener);
  opener.postMessage({ type: READY }, location.origin);
  return () => window.removeEventListener('message', listener);
}
