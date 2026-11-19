// C13: do relays keep markers (with re-sent and "unpaired" versions), the
// counter event and append-only settings events from fresh keys, and for how
// long? (D7, D12, D17)
//
// "Publish a test set" writes, from new random keys:
//   marker:   kind 30078 at a random d tag, version 1 ("paired"), then version 2
//             ("unpaired", newer), then version 1 again (an old device re-sending)
//   counter:  kind 30078 at a random d tag
//   settings: three kind 30078 events at distinct d tags (append-only)
// Content is random bytes, like encrypted content. The test set is remembered in
// this browser; "Re-check" later shows what each relay still has.

import { finalizeEvent, generateSecretKey, getPublicKey, type Event } from 'nostr-tools/pure';
import { Relay } from 'nostr-tools/relay';
import { Report, age, button, h, randomHex } from './ui';

const DEFAULT_RELAYS = [
    'wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net', 'wss://nostr.mom',
    'wss://nostr.bitcoiner.social', 'wss://nostr.oxtr.dev', 'wss://offchain.pub', 'wss://relay.nostr.band',
];
const KIND = 30078;
const STORE = 'checks_c13_runs';

interface Run {
    at: number;
    relays: string[];
    markerPub: string; markerD: string; markerV2Id: string;
    counterPub: string; counterD: string; counterId: string;
    settingsPub: string; settingsIds: string[];
    publish: Record<string, Record<string, string>>; // relay → event name → "ok" | error
}

const loadRuns = (): Run[] => {
    try { return JSON.parse(localStorage.getItem(STORE) ?? '[]'); } catch (_) { return []; }
};
const saveRuns = (runs: Run[]) => { try { localStorage.setItem(STORE, JSON.stringify(runs)); } catch (_) { /* ignore */ } };

const content = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(96))));

async function withRelay<T>(url: string, f: (r: Relay) => Promise<T>): Promise<T> {
    const relay = await Promise.race([
        Relay.connect(url),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('connect timeout')), 8000)),
    ]);
    try { return await f(relay); } finally { relay.close(); }
}

const publishOne = (relay: Relay, e: Event) =>
    Promise.race([
        relay.publish(e).then(() => 'ok'),
        new Promise<string>(res => setTimeout(() => res('timeout'), 8000)),
    ]).catch((err: Error) => String(err?.message ?? err));

function query(relay: Relay, filter: Record<string, unknown>): Promise<Event[]> {
    return new Promise(resolve => {
        const got: Event[] = [];
        const done = () => { clearTimeout(t); sub.close(); resolve(got); };
        const sub = relay.subscribe([filter as never], { onevent: e => got.push(e), oneose: done });
        const t = setTimeout(done, 8000);
    });
}

async function publishSet(relays: string[], r: Report): Promise<Run> {
    const now = Math.floor(Date.now() / 1000);
    const mk = generateSecretKey(), ck = generateSecretKey(), sk = generateSecretKey();
    const markerD = randomHex(32), counterD = randomHex(32), sPrefix = randomHex(16);
    const ev = (key: Uint8Array, d: string, at: number) =>
        finalizeEvent({ kind: KIND, created_at: at, tags: [['d', d]], content: content() }, key);
    const markerV1 = ev(mk, markerD, now - 20);
    const markerV2 = ev(mk, markerD, now - 10);
    const counter = ev(ck, counterD, now);
    const settings = [0, 1, 2].map(i => ev(sk, `${sPrefix}:${i}`, now - 2 + i));
    const run: Run = {
        at: Date.now(), relays,
        markerPub: getPublicKey(mk), markerD, markerV2Id: markerV2.id,
        counterPub: getPublicKey(ck), counterD, counterId: counter.id,
        settingsPub: getPublicKey(sk), settingsIds: settings.map(e => e.id),
        publish: {},
    };
    await Promise.all(relays.map(async url => {
        const res: Record<string, string> = {};
        try {
            await withRelay(url, async relay => {
                res.markerV1 = await publishOne(relay, markerV1);
                res.markerV2 = await publishOne(relay, markerV2);
                res.markerV1again = await publishOne(relay, markerV1);
                res.counter = await publishOne(relay, counter);
                for (const [i, e] of settings.entries()) res[`settings${i}`] = await publishOne(relay, e);
            });
        } catch (e) { res.connect = String((e as Error).message ?? e); }
        run.publish[url] = res;
        const bad = Object.entries(res).filter(([k, v]) => v !== 'ok' && !(k === 'markerV1again' && /replaced|newer|duplicate|have/i.test(v)));
        if (bad.length === 0) r.pass(`${url}: accepted all (re-sent old marker: ${res.markerV1again})`);
        else r.warn(`${url}: ${bad.map(([k, v]) => `${k}=${v}`).join(', ')}`);
    }));
    return run;
}

async function recheck(run: Run, r: Report): Promise<void> {
    r.info(`Test set from ${new Date(run.at).toISOString()} (${age(Date.now() - run.at)} ago)`);
    await Promise.all(run.relays.map(async url => {
        try {
            await withRelay(url, async relay => {
                const marker = await query(relay, { kinds: [KIND], authors: [run.markerPub], '#d': [run.markerD] });
                const counter = await query(relay, { kinds: [KIND], authors: [run.counterPub], '#d': [run.counterD] });
                const settings = await query(relay, { kinds: [KIND], authors: [run.settingsPub] });
                const m = marker.length === 0 ? 'missing'
                    : marker.some(e => e.id === run.markerV2Id) && marker.length === 1 ? 'v2 (newest) ✓'
                        : marker.some(e => e.id === run.markerV2Id) ? `v2 plus ${marker.length - 1} older` : 'OLD v1 ✗';
                const s = run.settingsIds.filter(id => settings.some(e => e.id === id)).length;
                const line = `${url}: marker ${m}; counter ${counter.length ? 'kept' : 'missing'}; settings ${s}/3`;
                if (m === 'v2 (newest) ✓' && counter.length && s === 3) r.pass(line);
                else r.warn(line);
            });
        } catch (e) { r.fail(`${url}: ${String((e as Error).message ?? e)}`); }
    }));
}

export function viewC13(r: Report): HTMLElement {
    const relays = h('textarea', { value: DEFAULT_RELAYS.join('\n'), rows: 8, style: 'width:100%' });
    const runsEl = h('div');
    const renderRuns = () => {
        runsEl.replaceChildren(...loadRuns().map((run, i) =>
            h('p', {}, `Test set ${i + 1}: ${new Date(run.at).toLocaleString()} (${age(Date.now() - run.at)} ago) `,
                button('Re-check', () => recheck(run, r)))));
    };
    renderRuns();
    return h('div', {},
        h('p', {}, 'Relays, one per line:'), relays,
        h('p', {}, button('Publish a test set', async () => {
            const list = relays.value.split(/\s+/).filter(u => /^wss:\/\//.test(u));
            r.info(`Publishing to ${list.length} relays…`);
            const run = await publishSet(list, r);
            saveRuns([...loadRuns(), run]);
            renderRuns();
            r.info('Saved. Re-check now, then again after 1 day, 1 week and 1 month.');
        })),
        runsEl,
    );
}
