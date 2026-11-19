// C8: storage in a partitioned third-party iframe (D6, D11, D23): a
// non-extractable WebCrypto key in IndexedDB, localStorage, OPFS with a sync
// access handle in a worker (what Evolu's SQLite needs), and how long each
// survives (Safari clears script-written storage after about 7 days of no use).
// Evolu itself is tried in a later step if these work.

import { Report, age, crossFrame, h, originPicker, otherOrigin } from './ui';

const DB = 'checks_c8';

function idb<T>(f: (s: IDBObjectStore) => IDBRequest<T>, mode: IDBTransactionMode = 'readonly'): Promise<T> {
    return new Promise((resolve, reject) => {
        const open = indexedDB.open(DB, 1);
        open.onupgradeneeded = () => open.result.createObjectStore('kv');
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
            const tx = open.result.transaction('kv', mode);
            const req = f(tx.objectStore('kv'));
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        };
    });
}

interface Saved { key: CryptoKey; iv: Uint8Array; ct: ArrayBuffer; createdAt: number; lastSeen: number }

export async function runStorage(r: Report): Promise<void> {
    r.info(`${location.origin} as ${window.top === window ? 'top-level page' : 'iframe in ' + (location.ancestorOrigins?.[0] ?? document.referrer)}`);
    if ('hasStorageAccess' in document) r.info(`hasStorageAccess(): ${await document.hasStorageAccess()}`);
    try {
        r.info(`storage.persisted(): ${await navigator.storage?.persisted?.()}; estimate quota ${Math.round(((await navigator.storage.estimate()).quota ?? 0) / 1e6)} MB`);
    } catch (e) { r.info(`storage API: ${(e as Error).message}`); }

    // localStorage
    try {
        const prev = localStorage.getItem('checks_c8_created');
        if (prev) r.pass(`localStorage kept for ${age(Date.now() - Number(prev))}`);
        else { localStorage.setItem('checks_c8_created', String(Date.now())); r.info('localStorage: first visit, value written'); }
    } catch (e) { r.fail(`localStorage: ${(e as Error).message}`); }

    // Non-extractable key in IndexedDB
    try {
        const saved = await idb<Saved | undefined>(s => s.get('key'));
        if (saved) {
            const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: saved.iv as BufferSource }, saved.key, saved.ct);
            const okText = new TextDecoder().decode(pt) === 'device secret works';
            r[okText ? 'pass' : 'fail'](`Non-extractable key in IndexedDB kept for ${age(Date.now() - saved.createdAt)} (last visit ${age(Date.now() - saved.lastSeen)} ago); decrypt ${okText ? 'works' : 'FAILED'}; extractable=${saved.key.extractable}`);
            await idb(s => s.put({ ...saved, lastSeen: Date.now() }, 'key'), 'readwrite');
        } else {
            const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode('device secret works'));
            await idb(s => s.put({ key, iv, ct, createdAt: Date.now(), lastSeen: Date.now() }, 'key'), 'readwrite');
            r.info('IndexedDB: first visit, non-extractable key stored. Come back later to see how long it lasts.');
        }
    } catch (e) { r.fail(`IndexedDB / non-extractable key: ${(e as Error).message}`); }

    // OPFS: plain access, then a sync access handle in a dedicated worker.
    try {
        const root = await navigator.storage.getDirectory();
        const f = await root.getFileHandle('checks_c8.txt', { create: true });
        const w = await f.createWritable();
        await w.write('opfs ok');
        await w.close();
        r.pass('OPFS: file written from the page');
    } catch (e) { r.fail(`OPFS from the page: ${(e as Error).message}`); }
    try {
        const worker = new Worker(new URL('./c8-worker.ts', import.meta.url), { type: 'module' });
        const res = await new Promise<string>((resolve) => {
            const t = setTimeout(() => resolve('timeout'), 8000);
            worker.onmessage = e => { clearTimeout(t); resolve(String(e.data)); };
            worker.onerror = e => { clearTimeout(t); resolve(`worker error: ${e.message}`); };
        });
        worker.terminate();
        r[res.startsWith('ok') ? 'pass' : 'fail'](`OPFS sync access handle in a worker: ${res}`);
    } catch (e) { r.fail(`Worker: ${(e as Error).message}`); }
    r.info(`SharedWorker ${typeof SharedWorker === 'undefined' ? 'not available' : 'available'}; BroadcastChannel ${typeof BroadcastChannel === 'undefined' ? 'not available' : 'available'}`);
}

export function hostC8(r: Report): HTMLElement {
    const box = h('div');
    const mount = () => box.replaceChildren(crossFrame('C8', otherOrigin()));
    mount();
    void runStorage(r);
    return h('div', {},
        h('p', {}, 'The results below are for this page at top level. The dashed iframe runs the same checks as a third-party iframe: copy its report too. Revisit this page after 1, 3, 7 and 10 days (Safari: without opening the other origin in between) to see what survived.'),
        originPicker(mount),
        box,
    );
}
