// The v1 check kit (#73, "Checks before building"). One page, routed by ?c=:
//   checks.html                  the list
//   checks.html?c=C19            a check, top level (the host page)
//   checks.html?c=C19&role=frame the same check inside the cross-site iframe
//   checks.html?c=C19&role=tab   the tab opened by that iframe
// Results are copied as Markdown into the results issue.

import '../lib/bufferBase64url'; // before Evolu (see the file)
import { runC12 } from './c12';
import { viewC13 } from './c13';
import { frameC19, hostC19, tabC19 } from './c19';
import { hostC8, runStorage } from './c8';
import { hostEvolu, viewEvolu } from './evolu';
import { hostPrf, viewPrf } from './prf';
import { Report, app, h, params, role } from './ui';
import { hostW3A, viewW3A } from './w3a';

interface Check {
    id: string;
    title: string;
    checks: string;
    how: string;
    top: (r: Report) => HTMLElement | Promise<HTMLElement>;
    frame?: (r: Report) => HTMLElement;
    tab?: (r: Report) => HTMLElement;
}

const CHECKS: Check[] = [
    {
        id: 'C12', title: 'Derivation test vectors', checks: 'C12',
        how: 'Runs by itself. Open it in every browser you have.',
        top: r => { void runC12(r); return h('div'); },
    },
    {
        id: 'C19', title: 'Tab handshake', checks: 'C19',
        how: 'Follow the steps on the page. Copy the report from the tab.',
        top: hostC19, frame: frameC19, tab: tabC19,
    },
    {
        id: 'C8', title: 'Storage in a cross-site iframe', checks: 'C8 (storage part)',
        how: 'Open once, copy both reports, then revisit after 1, 3, 7 and 10 days.',
        top: hostC8, frame: r => { void runStorage(r); return h('div'); },
    },
    {
        id: 'EVOLU', title: 'Evolu in a cross-site iframe', checks: 'C8 (Evolu part), D11',
        how: 'Write rows at top level and in the iframe; they should sync between the two and survive reloads.',
        top: hostEvolu, frame: viewEvolu,
    },
    {
        id: 'C13', title: 'Do relays keep our events?', checks: 'C13',
        how: 'Publish a test set, re-check now, then after 1 day, 1 week and 1 month (same browser).',
        top: viewC13,
    },
    {
        id: 'W3A', title: 'Web3Auth lab', checks: 'C1, C7, C16, C17, C18',
        how: 'Needs test client IDs allowlisted for both origins. See the procedures in the results issue.',
        top: hostW3A, frame: viewW3A,
    },
    {
        id: 'PRF', title: 'Passkey PRF', checks: 'C5, C20',
        how: 'Create a test passkey and use it twice, at top level and in the iframe.',
        top: hostPrf, frame: viewPrf,
    },
];

async function render() {
    const id = params.get('c');
    const check = CHECKS.find(c => c.id === id);
    if (!check) {
        document.title = 'v1 checks';
        app.append(
            h('h1', { textContent: 'nostr-shard-signer v1 checks' }),
            h('p', {}, 'Checks from issue #73. Run each in the browsers listed there and paste the copied reports into the results issue. Nothing here touches your real signer data; test passkeys and Web3Auth test sessions should be removed afterwards.'),
            h('table', {},
                h('tr', {}, h('th', { textContent: 'Page' }), h('th', { textContent: 'Checks' }), h('th', { textContent: 'How' })),
                ...CHECKS.map(c => h('tr', {},
                    h('td', {}, h('a', { href: `?c=${c.id}`, textContent: c.title })),
                    h('td', { textContent: c.checks }),
                    h('td', { textContent: c.how }))),
            ),
        );
        return;
    }
    document.title = `${check.id} check`;
    const r = new Report(check.id);
    const view = role === 'frame' ? check.frame : role === 'tab' ? check.tab : check.top;
    if (!view) {
        app.append(h('p', { textContent: `This check has no "${role}" page.` }));
        return;
    }
    app.append(
        role === 'top' ? h('p', {}, h('a', { href: '?', textContent: '← all checks' })) : '',
        h(role === 'top' ? 'h1' : 'h3', { textContent: `${check.title} (${check.checks})${role === 'top' ? '' : ` — ${role} on ${location.host}`}` }),
        await view(r),
        r.view(),
    );
}

void render();
