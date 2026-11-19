// C19: the tab handshake (D24). The host page (top level, origin A) embeds this
// page from origin B as an iframe ("frame"); the frame opens a top-level tab of
// origin B ("tab"). The tab and the frame talk with postMessage through
// window.opener, the frame hands over a test store, and the tab watches for the
// frame going away (host closed, navigated, or iframe removed).

import { Report, button, crossFrame, h, otherOrigin, originPicker, pageUrl, randomHex } from './ui';

const T = 'checks-c19';

export function hostC19(r: Report): HTMLElement {
    const box = h('div');
    const mount = () => box.replaceChildren(crossFrame('C19', otherOrigin()));
    mount();
    return h('div', {},
        originPicker(mount),
        h('ol', {},
            h('li', {}, 'In the dashed iframe below, click "Open the signer tab".'),
            h('li', {}, 'In the new tab, check the results, then come back here.'),
            h('li', {}, 'Click "Remove the iframe" or "Navigate this page away", then look at the tab again: it should say the store was dropped.'),
            h('li', {}, 'Copy the report from the tab (it has the full results).'),
        ),
        box,
        h('p', {},
            button('Remove the iframe', () => box.replaceChildren()), ' ',
            button('Navigate this page away', () => { location.href = 'about:blank'; }),
        ),
    );
}

export function frameC19(r: Report): HTMLElement {
    let tab: Window | null = null;
    const store = { secret: randomHex(16), createdAt: Date.now() };
    try { localStorage.setItem('checks_c19_frame', store.secret); } catch (_) { /* ignore */ }
    const site = (location.ancestorOrigins?.[0]) ?? document.referrer ?? '?';
    r.info(`Frame on ${location.origin}, embedded by ${site}`);
    window.addEventListener('message', e => {
        if (e.origin !== location.origin || e.source !== tab) return;
        if (e.data?.type === `${T}-hello`) {
            r.pass('Tab said hello through window.opener');
            tab!.postMessage({ type: `${T}-store`, store, site }, location.origin);
        }
    });
    window.addEventListener('pagehide', () => {
        try { tab?.postMessage({ type: `${T}-bye` }, location.origin); } catch (_) { /* ignore */ }
    });
    return h('div', {},
        button('Open the signer tab', () => {
            tab = window.open(pageUrl(location.origin, { c: 'C19', role: 'tab' }), '_blank');
            if (!tab) r.fail('window.open returned null (popup blocked?)');
            else r.info('Tab opened');
        }),
    );
}

export function tabC19(r: Report): HTMLElement {
    const status = h('h2', { textContent: 'Waiting for the widget…' });
    let have: { secret: string } | null = null;
    const drop = (why: string) => {
        if (!have) return;
        have = null;
        status.textContent = 'Store dropped';
        r.pass(`Store dropped: ${why}`);
    };
    void (async () => {
        try {
            const res = await fetch(location.href, { method: 'HEAD', cache: 'no-store' });
            const coop = res.headers.get('cross-origin-opener-policy');
            if (coop) r.warn(`This page is served with Cross-Origin-Opener-Policy: ${coop}`);
            else r.pass('No Cross-Origin-Opener-Policy header on this page');
        } catch (e) { r.info(`Couldn't read headers: ${(e as Error).message}`); }
    })();
    try {
        const seen = localStorage.getItem('checks_c19_frame');
        r.info(seen ? 'The tab sees the frame\'s localStorage (storage NOT partitioned)' : 'The tab doesn\'t see the frame\'s localStorage (storage partitioned)');
    } catch (_) { /* ignore */ }
    const opener = window.opener as Window | null;
    if (!opener) {
        r.fail('window.opener is null: the handshake is impossible here');
        status.textContent = 'No opener';
    } else {
        r.pass('window.opener is available');
        const timeout = setTimeout(() => {
            if (!have) { r.fail('No answer from the opener within 5 s'); status.textContent = "The widget that opened this isn't the real signer"; }
        }, 5000);
        window.addEventListener('message', e => {
            if (e.source !== opener) return;
            if (e.origin !== location.origin) { r.fail(`Message from another origin: ${e.origin}`); return; }
            if (e.data?.type === `${T}-store`) {
                clearTimeout(timeout);
                have = e.data.store;
                status.textContent = `Connected to the widget on ${e.data.site}`;
                r.pass(`Handshake done; store received (${e.data.store.secret.slice(0, 8)}…) from the widget on ${e.data.site}`);
            }
            if (e.data?.type === `${T}-bye`) drop('the frame sent pagehide');
        });
        opener.postMessage({ type: `${T}-hello` }, location.origin);
        const poll = setInterval(() => {
            let closed: boolean;
            try { closed = opener.closed; } catch (_) { closed = true; }
            if (closed) { clearInterval(poll); drop('window.opener.closed became true'); }
        }, 500);
    }
    return h('div', {}, status);
}
