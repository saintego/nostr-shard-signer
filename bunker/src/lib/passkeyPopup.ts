// Signer passkeys in a popup on the signer's own origin, for browsers that don't
// allow passkeys in a cross-origin iframe (evolustr SPEC §5.5 rule 5).
//
// The iframe opens the popup from the user's click (a popup opened without one
// is blocked), sends it the request, and gets the result back. The popup runs
// WebAuthn as a top-level page on the same origin, so the rpId is the same.
//
// The popup only serves its opener, and only when the opener is this same
// origin: otherwise any site could open it and read the passkey's PRF output.

import { webauthnPasskeys, type Passkeys } from '../vendor/evolustr/evolustr.js';

export const POPUP_PARAM = 'evolustr-passkey';

type Op =
    | { op: 'create'; args: Parameters<Passkeys['create']>[0] }
    | { op: 'get'; args: Parameters<Passkeys['get']>[0] };

let popup: Window | null = null;
/** The popup whose page has loaded and said so. */
let readyPopup: Window | null = null;

window.addEventListener('message', e => {
    if (e.source && e.source === popup && e.origin === location.origin &&
        (e.data as { type?: string })?.type === 'EVOLUSTR_PASSKEY_READY') readyPopup = popup;
});

/** Opens (or focuses) the popup. Call it synchronously from a click. */
export function openPasskeyPopup(): void {
    if (popup && !popup.closed) {
        popup.focus();
        return;
    }
    const url = new URL(location.href);
    url.search = `?${POPUP_PARAM}=1`;
    url.hash = '';
    popup = window.open(url.toString(), 'evolustr-passkey', 'popup,width=440,height=560');
}

function run<T>(request: Op): Promise<T> {
    return new Promise((resolve, reject) => {
        const w = popup;
        if (!w || w.closed) {
            reject(new Error('The passkey window was blocked. Allow popups for this site and try again.'));
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
            w.postMessage({ type: 'EVOLUSTR_PASSKEY_REQUEST', ...request }, location.origin);
        };
        const listener = (e: MessageEvent) => {
            if (e.source !== w || e.origin !== location.origin) return;
            const d = e.data as { type?: string; result?: unknown; error?: string };
            if (d?.type === 'EVOLUSTR_PASSKEY_READY') return send();  // the popup just loaded
            if (d?.type !== 'EVOLUSTR_PASSKEY_RESULT') return;
            done();
            if (typeof d.error === 'string') reject(new Error(d.error));
            else resolve(d.result as T);
        };
        // Closed without a result: the user closed it. Seen twice in a row, so
        // a result posted just before the popup closed itself still arrives.
        let closedSeen = 0;
        const closedPoll = setInterval(() => {
            closedSeen = w.closed ? closedSeen + 1 : 0;
            if (closedSeen < 2) return;
            done();
            reject(new Error('The passkey window was closed'));
        }, 500);
        window.addEventListener('message', listener);
        // Already loaded (the user clicked again while it was open): send now.
        if (readyPopup === w) send();
    });
}

/** `Passkeys` that run in the popup. */
export const popupPasskeys = (rpId: string): Passkeys => ({
    rpId,
    supported: async () => typeof PublicKeyCredential !== 'undefined',
    create: args => run({ op: 'create', args }),
    get: args => run({ op: 'get', args }),
});

// ── Inside the popup ──────────────────────────────────────────────────────────

export interface PopupRequest {
    op: 'create' | 'get';
    perform: () => Promise<void>;
}

/**
 * Wires the popup page: calls `onRequest` for each request from the opener.
 * The page shows a button and calls `perform()` from its click (Safari wants a
 * click in the popup itself before WebAuthn).
 */
export function servePasskeyPopup(onRequest: (r: PopupRequest | null) => void): () => void {
    const opener = window.opener as Window | null;
    if (!opener) {
        onRequest(null);
        return () => { };
    }
    const passkeys = webauthnPasskeys({ rpName: 'Nostr Shard Signer' });
    const listener = (e: MessageEvent) => {
        if (e.source !== opener || e.origin !== location.origin) return;
        const d = e.data as Partial<Op> & { type?: string };
        if (d?.type !== 'EVOLUSTR_PASSKEY_REQUEST' || (d.op !== 'create' && d.op !== 'get') || !d.args) return;
        const reply = (msg: Record<string, unknown>) =>
            opener.postMessage({ type: 'EVOLUSTR_PASSKEY_RESULT', ...msg }, location.origin);
        onRequest({
            op: d.op,
            perform: async () => {
                try {
                    const result = d.op === 'create'
                        ? await passkeys.create(d.args as Parameters<Passkeys['create']>[0])
                        : await passkeys.get(d.args as Parameters<Passkeys['get']>[0]);
                    reply({ result });
                } catch (err) {
                    reply({ error: (err as Error).message || 'The passkey step failed' });
                }
                // Each step opens its own popup, from its own click.
                window.close();
            },
        });
    };
    window.addEventListener('message', listener);
    opener.postMessage({ type: 'EVOLUSTR_PASSKEY_READY' }, location.origin);
    return () => window.removeEventListener('message', listener);
}
