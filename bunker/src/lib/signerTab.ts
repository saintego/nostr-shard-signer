// The signer in its own tab (opt-in, #73 D24, #90). The widget opens it from a
// click; the tab handshakes with its opener and, while it's open, shows this
// site's prompts on the signer's real address instead of the widget or a popup.
// Signing stays in the widget: no key or store crosses. The tab stops as soon
// as the widget goes away (its page closed or navigated), watching both the
// widget's pagehide message and window.opener.closed (browsers differ, C19).

import { adoptPromptWindow } from './confirmPopup';
import { checkOpener } from './globalPopup';

export const TAB_PARAM = 'signer-tab';

// ── In the widget ─────────────────────────────────────────────────────────────

let tab: Window | null = null;

/** Opens the signer's tab; call it synchronously from a click. */
export function openSignerTab(site: string, onConnected: (connected: boolean) => void): void {
  if (tab && !tab.closed) {
    tab.focus();
    return;
  }
  const url = new URL(location.href);
  const locale = url.searchParams.get('locale');
  url.search = `?${TAB_PARAM}=1`;
  if (locale) url.searchParams.set('locale', locale);
  url.hash = '';
  const w = window.open(url.toString(), '_blank'); // unnamed, with its opener (#77)
  if (!w) {
    onConnected(false);
    return;
  }
  tab = w;
  const listener = (e: MessageEvent) => {
    if (e.source !== w || e.origin !== location.origin) return;
    if ((e.data as { type?: string })?.type !== 'SIGNER_TAB_READY') return;
    w.postMessage({ type: 'SIGNER_TAB_HELLO', site }, location.origin);
    adoptPromptWindow(w);
    onConnected(true);
  };
  window.addEventListener('message', listener);
  const poll = setInterval(() => {
    if (!w.closed) return;
    clearInterval(poll);
    window.removeEventListener('message', listener);
    adoptPromptWindow(null);
    tab = null;
    onConnected(false);
  }, 500);
}

// The widget goes away: tell the tab, so it stops at once.
window.addEventListener('pagehide', () => {
  try {
    tab?.postMessage({ type: 'SIGNER_TAB_BYE' }, location.origin);
  } catch {
    // the tab is gone too
  }
});

// ── In the tab ────────────────────────────────────────────────────────────────

export type TabStatus = { state: 'waiting' } | { state: 'connected'; site: string } | { state: 'refused' } | { state: 'gone' };

/** Handshakes with the opener and reports the tab's status. */
export function serveSignerTab(signerPath: string, onStatus: (s: TabStatus) => void): () => void {
  const opener = window.opener as Window | null;
  if (!opener) {
    onStatus({ state: 'refused' });
    return () => {};
  }
  const listener = (e: MessageEvent) => {
    if (e.source !== opener || e.origin !== location.origin) return;
    const d = e.data as { type?: string; site?: string };
    if (d?.type === 'SIGNER_TAB_BYE') return onStatus({ state: 'gone' });
    if (d?.type !== 'SIGNER_TAB_HELLO' || typeof d.site !== 'string') return;
    const check = checkOpener(opener, d.site, signerPath);
    onStatus(check.ok ? { state: 'connected', site: d.site } : { state: 'refused' });
  };
  window.addEventListener('message', listener);
  const poll = setInterval(() => {
    let closed = true;
    try {
      closed = opener.closed;
    } catch {
      // unreadable: treat as gone
    }
    if (closed) {
      clearInterval(poll);
      onStatus({ state: 'gone' });
    }
  }, 500);
  opener.postMessage({ type: 'SIGNER_TAB_READY' }, location.origin);
  return () => {
    clearInterval(poll);
    window.removeEventListener('message', listener);
  };
}
