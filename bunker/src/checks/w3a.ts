// Web3Auth lab for C1, C7, C16, C17 and C18. Two independent Web3Auth
// instances (A and B), each with its own client ID, network and storage mode,
// plus storage snapshots so we can see exactly what Web3Auth writes where.
//
// Nothing secret is shown: snapshots list key names and value lengths only, and
// the key export (C17) shows only the resulting pubkey.

import { authConnector, Web3Auth, WEB3AUTH_NETWORK } from '@web3auth/modal';
import { getPublicKey } from 'nostr-tools/pure';
import { Report, button, crossFrame, fromHex, h, otherOrigin, originPicker, params, role } from './ui';

type Mode = 'default' | 'local-ns' | 'session-ns';

interface Adapter { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<void>; remove(k: string): Promise<void> }

// A class with only plain own fields: Web3Auth posts its connector settings
// (storage included) to the sign-in popup, and closures or a Storage object
// can't be cloned ("could not be cloned"). Methods on the prototype are fine.
class PrefixedStorage implements Adapter {
    constructor(readonly prefix: string, readonly session: boolean) { }
    private get store(): Storage { return this.session ? sessionStorage : localStorage; }
    async get(k: string) { return this.store.getItem(this.prefix + k); }
    async set(k: string, v: string) { this.store.setItem(this.prefix + k, v); }
    async remove(k: string) { this.store.removeItem(this.prefix + k); }
}
const adapter = (store: Storage, prefix: string): Adapter => new PrefixedStorage(prefix, store === sessionStorage);

function storageConfig(mode: Mode, name: string) {
    if (mode === 'default') return undefined;
    const a = adapter(mode === 'session-ns' ? sessionStorage : localStorage, `w3a_${name}_`);
    return { sessionId: a, accessToken: a, refreshToken: a, idToken: a };
}

// ── Storage snapshots ────────────────────────────────────────────────────────

type Snap = Map<string, number>;

async function snapshot(): Promise<Snap> {
    const s: Snap = new Map();
    const each = (label: string, st: Storage) => {
        try {
            for (let i = 0; i < st.length; i++) {
                const k = st.key(i)!;
                if (!k.startsWith('checks_')) s.set(`${label}: ${k}`, (st.getItem(k) ?? '').length);
            }
        } catch (_) { s.set(`${label}: (blocked)`, 0); }
    };
    each('localStorage', localStorage);
    each('sessionStorage', sessionStorage);
    for (const c of document.cookie.split(';').map(x => x.trim()).filter(Boolean))
        s.set(`cookie: ${c.split('=')[0]}`, c.length);
    try {
        for (const db of (await indexedDB.databases?.()) ?? [])
            if (db.name && !db.name.startsWith('checks_')) s.set(`IndexedDB: ${db.name}`, 0);
    } catch (_) { /* Firefox before 126 has no databases() */ }
    return s;
}

const fmt = (s: Snap) => [...s].map(([k, n]) => (n ? `${k} (${n} chars)` : k));

function diff(before: Snap, after: Snap): string[] {
    const out: string[] = [];
    for (const [k, n] of after) if (!before.has(k)) out.push(`+ ${k}${n ? ` (${n} chars)` : ''}`);
    else if (before.get(k) !== n) out.push(`~ ${k} (${before.get(k)} → ${n} chars)`);
    for (const k of before.keys()) if (!after.has(k)) out.push(`- ${k}`);
    return out;
}

/** Keys that look like a Web3Auth session, found without starting Web3Auth (D23). */
export const LEFTOVER_PATTERN = /auth_store|session_?id|access_?token|refresh_?token|id_?token|web3auth|openlogin|w3a_/i;

// ── One instance ─────────────────────────────────────────────────────────────

class Instance {
    w3a: Web3Auth | null = null;
    readonly clientId = h('input', { size: 40, placeholder: 'client ID' });
    readonly network = h('select', {},
        h('option', { value: 'sapphire_devnet', textContent: 'sapphire_devnet' }),
        h('option', { value: 'sapphire_mainnet', textContent: 'sapphire_mainnet' }));
    readonly mode = h('select', {},
        h('option', { value: 'default', textContent: 'default storage' }),
        h('option', { value: 'local-ns', textContent: 'own namespace (state in localStorage)' }),
        h('option', { value: 'session-ns', textContent: 'own namespace (state in sessionStorage)' }));
    readonly sessionTime = h('input', { size: 8, placeholder: 'default' });

    constructor(readonly name: 'A' | 'B', readonly r: Report, readonly snap: () => Promise<void>) {
        const saved = (k: string) => { try { return localStorage.getItem(`checks_w3a_${name}_${k}`); } catch (_) { return null; } };
        this.clientId.value = params.get(`clientId${name}`) ?? saved('clientId') ?? '';
        this.network.value = params.get(`network${name}`) ?? saved('network') ?? 'sapphire_devnet';
        this.mode.value = params.get(`mode${name}`) ?? saved('mode') ?? 'default';
        this.sessionTime.value = params.get(`sessionTime${name}`) ?? saved('sessionTime') ?? '';
    }

    /** What the report needs to be read without guessing: never the full client ID. */
    private settings(): string {
        const id = this.clientId.value.trim();
        return `client ID ${id.slice(0, 6)}…${id.slice(-4)}, ${this.network.value}, ${this.mode.value} storage` +
            (this.sessionTime.value ? `, sessionTime ${this.sessionTime.value}` : '');
    }

    private save() {
        try {
            localStorage.setItem(`checks_w3a_${this.name}_clientId`, this.clientId.value);
            localStorage.setItem(`checks_w3a_${this.name}_network`, this.network.value);
            localStorage.setItem(`checks_w3a_${this.name}_mode`, this.mode.value);
            localStorage.setItem(`checks_w3a_${this.name}_sessionTime`, this.sessionTime.value);
        } catch (_) { /* ignore */ }
    }

    private async step(what: string, f: () => Promise<string | void>) {
        const t0 = performance.now();
        try {
            const extra = await f();
            this.r.pass(`${this.name}: ${what} (${Math.round(performance.now() - t0)} ms)${extra ? ': ' + extra : ''}`);
        } catch (e) {
            const err = e as Error & { cause?: unknown; code?: unknown };
            const cause = err?.cause ? `; cause: ${(err.cause as Error)?.message ?? String(err.cause)}` : '';
            this.r.fail(`${this.name}: ${what} failed (${this.settings()}): ${err?.message ?? e}${err?.code ? ` [code ${err.code}]` : ''}${cause}`);
        }
        await this.snap();
    }

    init = () => this.step('init', async () => {
        this.save();
        if (!this.clientId.value) throw new Error('no client ID');
        const st = Number(this.sessionTime.value);
        this.w3a = new Web3Auth({
            clientId: this.clientId.value.trim(),
            web3AuthNetwork: this.network.value === 'sapphire_mainnet' ? WEB3AUTH_NETWORK.SAPPHIRE_MAINNET : WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
            ...(st > 0 ? { sessionTime: st } : {}),
            // The top-level `storage` only covers Web3Auth-state. The login tokens
            // (auth_store:*, refresh-token cookie) belong to the auth connector.
            // Its settings are posted to the sign-in popup, so only plain values
            // work there: custom storage adapters make Login hang. `sessionKey`
            // renames the token keys (auth_store_A:*), which is enough to keep
            // two instances apart; where the tokens live (localStorage, cookie)
            // can't be changed this way. Ours is listed first, so Web3Auth's
            // default auth connector is dropped as a duplicate.
            ...(storageConfig(this.mode.value as Mode, this.name) ? {
                storage: storageConfig(this.mode.value as Mode, this.name),
                connectors: [authConnector({
                    connectorSettings: { sessionKey: `auth_store_${this.name}` },
                } as Parameters<typeof authConnector>[0])],
            } : {}),
        } as ConstructorParameters<typeof Web3Auth>[0]);
        await this.w3a.init();
        // Web3Auth restores a cached session in the background after init()
        // returns, and reports the outcome with an event (see App.tsx).
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const w: any = this.w3a;
        let restore = 'no cached session';
        if (this.w3a.connected) restore = 'restored at once';
        else if (w.cachedConnector || w.connectedConnectorName) {
            restore = await new Promise<string>(resolve => {
                const done = (what: string) => () => {
                    clearTimeout(t);
                    for (const [ev, f] of handlers) w.removeListener?.(ev, f);
                    resolve(what);
                };
                const handlers: [string, () => void][] = [
                    ['connected', done('restored (after the connected event)')],
                    ['rehydration_error', done('NOT restored (rehydration_error)')],
                    ['errored', done('NOT restored (errored)')],
                ];
                for (const [ev, f] of handlers) w.on?.(ev, f);
                const t = setTimeout(done('no answer within 20 s'), 20_000);
            });
        }
        return `${this.settings()}; session: ${restore}`;
    });

    login = () => this.step('login with Google', async () => {
        if (!this.w3a) throw new Error('init first');
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        await this.w3a.connectTo('auth', { authConnection: 'google' } as any);
        return `connected: ${this.w3a.connected}`;
    });

    exportKey = () => this.step('key export (C17)', async () => {
        const provider = this.w3a?.connection?.ethereumProvider;
        if (!provider) throw new Error('not connected');
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const raw = await (provider as any).request({ method: 'private_key' }) as string;
        if (!/^[0-9a-f]{64}$/i.test(raw ?? '')) throw new Error(`no usable key (${typeof raw})`);
        return `works; pubkey ${getPublicKey(fromHex(raw.toLowerCase()))}`;
    });

    logout = () => this.step('logout', async () => {
        if (!this.w3a) throw new Error('init first');
        await this.w3a.logout();
    });

    view(): HTMLElement {
        return h('fieldset', {},
            h('legend', { textContent: `Instance ${this.name}` }),
            h('p', {}, 'Client ID: ', this.clientId),
            h('p', {}, this.network, ' ', this.mode, ' sessionTime (s): ', this.sessionTime),
            h('p', {},
                button('Init', this.init), ' ', button('Login (Google)', this.login), ' ',
                button('Key export', this.exportKey), ' ', button('Logout', this.logout)),
        );
    }
}

export function viewW3A(r: Report): HTMLElement {
    let last: Snap = new Map();
    const snapEl = h('pre', { style: 'white-space:pre-wrap;font-size:12px' });
    const doSnap = async () => {
        const now = await snapshot();
        const d = diff(last, now);
        if (last.size || d.length) r.info(`Storage changes: ${d.length ? d.join('; ') : 'none'}`);
        last = now;
        snapEl.textContent = fmt(now).join('\n') || '(empty)';
    };
    const a = new Instance('A', r, doSnap);
    const b = new Instance('B', r, doSnap);
    void snapshot().then(s => {
        last = s;
        snapEl.textContent = fmt(s).join('\n') || '(empty)';
        r.info(`At load (${role}): ${s.size} storage entries`);
    });
    const detect = button('Detect a leftover session (without starting Web3Auth)', async () => {
        const s = await snapshot();
        const hits = [...s.keys()].filter(k => LEFTOVER_PATTERN.test(k));
        r.info(hits.length ? `Leftover-looking keys: ${hits.join('; ')}` : 'No leftover-looking keys');
    });
    const reload = button('Reload page (keeps settings)', () => location.reload());
    // D23: when Web3Auth can't log out a session it restored (code 5113), the
    // signer must remove the session's keys itself. This tries exactly that.
    const wipe = button('Remove Web3Auth session keys (without Web3Auth)', async () => {
        const removed: string[] = [];
        for (const st of [localStorage, sessionStorage]) {
            for (const k of Object.keys(st)) if (/^auth_store[_:]|^w3a_[AB]_|^Web3Auth-state$/.test(k)) { st.removeItem(k); removed.push(k); }
        }
        for (const c of document.cookie.split(';').map(x => x.trim().split('=')[0]).filter(n => /^auth_store[_:]/.test(n))) {
            for (const path of ['/', location.pathname.replace(/[^/]*$/, '')])
                document.cookie = `${c}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${path}`;
            removed.push(`cookie ${c}`);
        }
        r.info(removed.length ? `Removed without Web3Auth: ${removed.join(', ')}` : 'No Web3Auth session keys to remove');
        await doSnap();
        const left = [...(await snapshot()).keys()].filter(k => /auth_store/.test(k));
        r[left.length ? 'fail' : 'pass'](left.length ? `Still there: ${left.join('; ')}` : 'No auth_store keys left');
    });
    return h('div', {},
        a.view(), b.view(),
        h('p', {}, button('Snapshot storage', doSnap), ' ', detect, ' ', wipe, ' ', reload),
        h('details', {}, h('summary', { textContent: 'Current storage (names and sizes only)' }), snapEl),
    );
}

export function hostW3A(r: Report): HTMLElement {
    const box = h('div');
    const mount = () => box.replaceChildren(crossFrame('W3A', otherOrigin(),
        'publickey-credentials-get *; publickey-credentials-create *'));
    return h('div', {},
        h('p', {}, 'Top level: the lab runs right here. For the iframe case (C16), embed it from the other origin:'),
        originPicker(() => box.childElementCount && mount()),
        h('p', {}, button('Embed the lab from the other origin', mount)),
        box,
        viewW3A(r),
    );
}
