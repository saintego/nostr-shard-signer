// Sensitive prompts in a top-level window on the signer's own origin (#62).
//
// Inside the iframe, the embedding page can hide or cover a prompt so that one
// click approves something the user didn't see. No page can frame or style a
// popup. In shared mode (any site may embed the signer), the iframe shows a
// neutral "Review this request" button instead; its click opens this popup,
// which shows the prompt and sends back the answer. Closing it rejects.
//
// Same pattern as src/lib/passkeyPopup.ts: the popup only serves its opener,
// and only when the opener is this same origin.

import type { EvolustrAnswer, EvolustrPrompt } from '../types';
import type { BackupMethod } from './backup';

export const CONFIRM_PARAM = 'confirm';

/** What the popup shows. `origin` is the verified host page, from the iframe. */
export type ConfirmPopupRequest =
    | { kind: 'rpc'; origin: string; method: string; params: string[] }
    | { kind: 'evolustr'; origin: string; prompt: EvolustrPrompt }
    /** Key export; `privateKeyHex` lets the popup encrypt a backup itself. */
    | { kind: 'export'; nsecStr: string; npubStr: string; privateKeyHex: string; shared: boolean };

export type ConfirmPopupAnswer = 'approve' | 'reject' | EvolustrAnswer | 'done';

/** Sent while the popup stays open (key export). */
export type ConfirmPopupEvent = { backedUp: BackupMethod };

let popup: Window | null = null;
let readyPopup: Window | null = null;

window.addEventListener('message', e => {
    if (e.source && e.source === popup && e.origin === location.origin &&
        (e.data as { type?: string })?.type === 'CONFIRM_POPUP_READY') readyPopup = popup;
});

/** Opens (or focuses) the popup. Call it synchronously from a click. */
export function openConfirmPopup(): void {
    if (popup && !popup.closed) {
        popup.focus();
        return;
    }
    const url = new URL(location.href);
    url.search = `?${CONFIRM_PARAM}=1`;
    url.hash = '';
    readyPopup = null;
    popup = window.open(url.toString(), 'nostr-signer-confirm', 'popup,width=440,height=620');
}

/** Sends a request to the open popup and waits for the answer; closing it answers "closed". */
export function askInPopup(request: ConfirmPopupRequest, onEvent?: (e: ConfirmPopupEvent) => void): Promise<ConfirmPopupAnswer | 'closed'> {
    return new Promise((resolve, reject) => {
        const w = popup;
        if (!w || w.closed) {
            reject(new Error('The confirmation window was blocked. Allow popups for this site and try again.'));
            return;
        }
        let sent = false;
        const done = () => {
            clearInterval(closedPoll);
            window.removeEventListener('message', listener);
        };
        const send = () => {
            if (sent) return;
            sent = true;
            w.postMessage({ type: 'CONFIRM_POPUP_REQUEST', request }, location.origin);
        };
        const listener = (e: MessageEvent) => {
            if (e.source !== w || e.origin !== location.origin) return;
            const d = e.data as { type?: string; answer?: ConfirmPopupAnswer; event?: ConfirmPopupEvent };
            if (d?.type === 'CONFIRM_POPUP_READY') return send();
            if (d?.type === 'CONFIRM_POPUP_EVENT' && d.event) return onEvent?.(d.event);
            if (d?.type !== 'CONFIRM_POPUP_ANSWER' || typeof d.answer !== 'string') return;
            done();
            resolve(d.answer);
        };
        // Seen closed twice in a row, so an answer posted just before closing still arrives.
        let closedSeen = 0;
        const closedPoll = setInterval(() => {
            closedSeen = w.closed ? closedSeen + 1 : 0;
            if (closedSeen < 2) return;
            done();
            resolve('closed');
        }, 300);
        window.addEventListener('message', listener);
        if (readyPopup === w) send();
    });
}

// ── Inside the popup ──────────────────────────────────────────────────────────

export interface ServedRequest {
    request: ConfirmPopupRequest;
    answer: (a: ConfirmPopupAnswer) => void;
    event: (e: ConfirmPopupEvent) => void;
}

/** Wires the popup page: calls `onRequest` with the opener's request, or null without an opener. */
export function serveConfirmPopup(onRequest: (r: ServedRequest | null) => void): () => void {
    const opener = window.opener as Window | null;
    if (!opener) {
        onRequest(null);
        return () => { };
    }
    const post = (msg: Record<string, unknown>) => opener.postMessage(msg, location.origin);
    const listener = (e: MessageEvent) => {
        if (e.source !== opener || e.origin !== location.origin) return;
        const d = e.data as { type?: string; request?: ConfirmPopupRequest };
        if (d?.type !== 'CONFIRM_POPUP_REQUEST' || !d.request) return;
        onRequest({
            request: d.request,
            answer: a => {
                post({ type: 'CONFIRM_POPUP_ANSWER', answer: a });
                window.close();
            },
            event: ev => post({ type: 'CONFIRM_POPUP_EVENT', event: ev }),
        });
    };
    window.addEventListener('message', listener);
    post({ type: 'CONFIRM_POPUP_READY' });
    return () => window.removeEventListener('message', listener);
}
