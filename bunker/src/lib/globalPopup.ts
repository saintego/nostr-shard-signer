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
// Never: the login key or the root; they stay in the popup's memory.

import { parseSiteGrant, type SiteGrant } from './siteGrant';

export const GLOBAL_PARAM = 'global-signin';

export interface GlobalRequest {
  readonly type: 'NSS_GLOBAL_REQUEST';
  /** The site's origin, as the widget verified it (its parent). */
  readonly site: string;
}

export interface GlobalResult {
  readonly type: 'NSS_GLOBAL_RESULT';
  readonly grant?: SiteGrant;
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
function parseResult(d: Partial<Omit<GlobalResult, 'type'>>): SiteGrant | Error {
  if (typeof d.error === 'string') return new Error(d.error);
  return parseSiteGrant(d.grant) ?? new Error('The sign-in window sent an invalid answer');
}

/**
 * Talks to the popup: sends the site once it says it's ready, resolves with its
 * result. Rejects when the popup closes without one.
 */
export function awaitGlobalResult(popup: Window, site: string): Promise<SiteGrant> {
  return new Promise((resolve, reject) => {
    const done = () => {
      clearInterval(closedPoll);
      window.removeEventListener('message', listener);
    };
    const listener = (e: MessageEvent) => {
      if (e.source !== popup || e.origin !== location.origin) return;
      const d = e.data as Partial<Omit<GlobalResult, 'type'>> & { type?: string };
      if (d?.type === READY) {
        const request: GlobalRequest = { type: 'NSS_GLOBAL_REQUEST', site };
        popup.postMessage(request, location.origin);
        return;
      }
      if (d?.type !== 'NSS_GLOBAL_RESULT') return;
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

/**
 * Wires the popup page: tells the opener it's ready, and calls `onRequest`
 * with the site once the opener asks and passes `checkOpener`.
 */
export function serveGlobalPopup(
  signerPath: string,
  onRequest: (site: string, reply: (result: Omit<GlobalResult, 'type'>) => void) => void,
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
    onRequest(d.site, (result) =>
      opener.postMessage({ type: 'NSS_GLOBAL_RESULT', ...result }, location.origin)
    );
  };
  window.addEventListener('message', listener);
  opener.postMessage({ type: READY }, location.origin);
  return () => window.removeEventListener('message', listener);
}
