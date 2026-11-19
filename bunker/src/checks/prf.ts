// C5 / C20: passkey PRF, at top level and in a cross-site iframe. Creates a
// test passkey ("nostr-shard-signer check"), then asks it twice for the PRF
// output and checks both answers are equal. Outputs are compared, never shown.

import { Report, button, crossFrame, h, hex, originPicker, otherOrigin } from './ui';

const SALT = new TextEncoder().encode('nostr-shard-signer/checks/prf-salt-0000000000000000').slice(0, 32);
const KEY = 'checks_prf_credential';

const b64u = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

type PrfResults = { enabled?: boolean; results?: { first?: ArrayBuffer } };

async function create(r: Report) {
    try {
        const cred = await navigator.credentials.create({
            publicKey: {
                rp: { name: 'Nostr Shard Signer checks', id: location.hostname },
                user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'prf-check', displayName: 'nostr-shard-signer check' },
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
                authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
                extensions: { prf: { eval: { first: SALT } } } as AuthenticationExtensionsClientInputs,
            },
        }) as PublicKeyCredential | null;
        if (!cred) return r.fail('create: no credential');
        const prf = (cred.getClientExtensionResults() as { prf?: PrfResults }).prf;
        try { localStorage.setItem(KEY, b64u(cred.rawId)); } catch (_) { /* ignore */ }
        r[prf?.enabled ? 'pass' : 'fail'](`create: prf.enabled=${prf?.enabled}; result at create: ${prf?.results?.first ? 'yes' : 'no'}; attachment ${(cred as PublicKeyCredential & { authenticatorAttachment?: string }).authenticatorAttachment ?? '?'}`);
    } catch (e) { r.fail(`create: ${(e as Error).name}: ${(e as Error).message}`); }
}

async function getOnce(): Promise<Uint8Array | null> {
    let id: string | null = null;
    try { id = localStorage.getItem(KEY); } catch (_) { /* ignore */ }
    const cred = await navigator.credentials.get({
        publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rpId: location.hostname,
            userVerification: 'required',
            ...(id ? { allowCredentials: [{ type: 'public-key' as const, id: unb64u(id) }] } : {}),
            extensions: { prf: { eval: { first: SALT } } } as AuthenticationExtensionsClientInputs,
        },
    }) as PublicKeyCredential | null;
    const first = (cred?.getClientExtensionResults() as { prf?: PrfResults })?.prf?.results?.first;
    return first ? new Uint8Array(first) : null;
}

async function getTwice(r: Report) {
    try {
        const a = await getOnce();
        if (!a) return r.fail('get: no PRF output');
        const b = await getOnce();
        if (!b) return r.fail('second get: no PRF output');
        const same = hex(a) === hex(b);
        r[same ? 'pass' : 'fail'](`get ×2: PRF output ${a.length} bytes, ${same ? 'identical' : 'DIFFERENT'} both times`);
    } catch (e) { r.fail(`get: ${(e as Error).name}: ${(e as Error).message}`); }
}

export function viewPrf(r: Report): HTMLElement {
    r.info(`${window.top === window ? 'Top level' : 'Iframe'} on ${location.origin}; WebAuthn ${typeof PublicKeyCredential === 'undefined' ? 'missing' : 'available'}`);
    return h('p', {},
        button('1. Create a test passkey', () => create(r)), ' ',
        button('2. Use it twice', () => getTwice(r)),
    );
}

export function hostPrf(r: Report): HTMLElement {
    const box = h('div');
    const mount = () => box.replaceChildren(crossFrame('PRF', otherOrigin(),
        'publickey-credentials-get *; publickey-credentials-create *'));
    mount();
    return h('div', {},
        h('p', {}, 'Run 1 and 2 here (top level), then inside the dashed iframe (cross-site). Delete the test passkeys afterwards in your passkey manager ("Nostr Shard Signer checks").'),
        viewPrf(r),
        originPicker(mount),
        box,
    );
}
