// Self-test of the production build setup (#86, review 7 of #73): the same Vite
// config and polyfills as the signer, so the derivation vectors, the patched
// Buffer and Evolu are checked as they run in the shipped bundle, not only as
// sources. Not deployed; tests/selftest.spec.js loads it and reads
// window.selftest.

import '../lib/bufferBase64url';
import { Buffer as PolyBuffer } from 'buffer';
import { getPublicKey } from 'nostr-tools/pure';
import { deriveIdentity, deriveRoot } from '../lib/derive';
import vectors from '../lib/derive.vectors.json';

// The worst case for Evolu: a global Buffer (the polyfill's, as Web3Auth's code
// puts in place in the signer) exists before Evolu loads, so Evolu uses it with
// "base64url". Evolu is imported only after this, below.
const g = globalThis as { Buffer?: unknown };
g.Buffer ??= PolyBuffer;

// Counts the browser's persistent-storage requests: the signer never asks
// (Firefox shows a prompt for it, #101), though Evolu would after a write.
let persistCalls = 0;
if (navigator.storage?.persist) {
  const persist = navigator.storage.persist.bind(navigator.storage);
  navigator.storage.persist = () => {
    persistCalls++;
    return persist();
  };
}

interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (s: string) =>
  new Uint8Array((s.match(/../g) ?? []).map((h) => Number.parseInt(h, 16)));

async function derivation(): Promise<Check> {
  for (const v of vectors.vectors) {
    const root = await deriveRoot(fromHex(v.globalLoginKey));
    if (hex(root) !== v.root.secret) return { name: 'derivation', ok: false, detail: 'root' };
    for (const id of v.identities) {
      const k = await deriveIdentity(root, id.index);
      if (hex(k) !== id.secret || getPublicKey(k) !== id.pubkey)
        return { name: 'derivation', ok: false, detail: `identity ${id.index}` };
    }
  }
  return { name: 'derivation', ok: true };
}

function buffer(): Check {
  const B = (globalThis as { Buffer?: typeof import('buffer').Buffer }).Buffer;
  // The signer has one (Web3Auth's polyfill): without it this check would prove nothing.
  if (!B) return { name: 'buffer', ok: false, detail: 'no global Buffer' };
  const bytes = Uint8Array.from([251, 255, 0, 62, 63]);
  const url = B.from(bytes).toString('base64url' as BufferEncoding);
  const back = new Uint8Array(B.from(url, 'base64url' as BufferEncoding));
  const plain = B.from(bytes).toString('base64');
  const ok =
    url === '-_8APj8' &&
    hex(back) === hex(bytes) &&
    plain === '+/8APj8=' &&
    B.from('ab', 'hex')[0] === 0xab;
  return { name: 'buffer', ok, detail: `${url} ${plain}` };
}

async function evolu(): Promise<Check> {
  const { openSiteStore, siteSchema } = await import('../lib/evoluStore');
  const { createQueryBuilder, NonEmptyTrimmedString100 } = await import('@evolu/common');
  const store = await openSiteStore(crypto.getRandomValues(new Uint8Array(32)), { sync: false });
  await new Promise<void>((resolve) => {
    store.insert(
      'setting',
      { name: NonEmptyTrimmedString100.orThrow('selftest'), value: 'ok' },
      { onComplete: resolve }
    );
  });
  const createQuery = createQueryBuilder(siteSchema);
  const rows = await store.loadQuery(
    createQuery((db) => db.selectFrom('setting').select(['name', 'value']))
  );
  const ok = rows.some((r) => r.name === 'selftest' && r.value === 'ok');
  return { name: 'evolu', ok, detail: `${rows.length} rows` };
}

/** The global list on Evolu, in memory (#84): add, pair, unpair, read back. */
async function globalList(): Promise<Check> {
  const { openGlobalList } = await import('../lib/globalList');
  const root = crypto.getRandomValues(new Uint8Array(32));
  const list = await openGlobalList(root, { sync: false });
  const pubkey = 'ab'.repeat(32);
  await list.addDerived(0, pubkey, 'https://example.com/x', 'Main');
  await list.pair(pubkey, 'https://example.com');
  await list.pair(pubkey, 'https://other.example');
  await list.unpair(pubkey, 'https://other.example');
  const rows = await list.load();
  await list.close(0);
  const ok =
    list.synced === 'NoRelays' &&
    rows.length === 1 &&
    rows[0]?.label === 'Main' &&
    rows[0]?.createdOn === 'https://example.com' &&
    JSON.stringify(rows[0]?.sites) === '["https://example.com"]';
  return { name: 'globalList', ok, detail: JSON.stringify(rows) };
}

/** The allowed-apps rows (#88): allow, forget, and read back after reopening. */
async function syncedApps(): Promise<Check> {
  const { openSyncedApps } = await import('../lib/syncedApps');
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const first = await openSyncedApps(secret, { sync: false });
  await first.allow('app-a');
  await first.allow('app-b');
  await first.forget('app-b');
  await first.allow('app-a'); // again: still one row
  await first.close();
  const again = await openSyncedApps(secret, { sync: false });
  const rows = await again.rows();
  await again.close();
  const sorted = [...rows].sort((x, y) => x.appId.localeCompare(y.appId));
  const ok =
    JSON.stringify(sorted) ===
    JSON.stringify([
      { appId: 'app-a', deleted: false },
      { appId: 'app-b', deleted: true },
    ]);
  return { name: 'syncedApps', ok, detail: JSON.stringify(sorted) };
}

/** After the Evolu checks wrote to stored databases: no persistent-storage request (#101). */
async function noPersistPrompt(): Promise<Check> {
  await new Promise((r) => setTimeout(r, 300));
  return { name: 'noPersistPrompt', ok: persistCalls === 0, detail: `${persistCalls} calls` };
}

async function siteCache(): Promise<Check> {
  const { saveSiteCache, loadSiteCache, deleteSiteCache } = await import('../lib/siteCache');
  const cache = {
    storeKey: 'a'.repeat(64),
    identities: [{ secretKey: 'b'.repeat(64), pubkey: 'c'.repeat(64), label: null }],
    active: 'c'.repeat(64),
    createdAt: Date.now(),
  };
  await saveSiteCache(cache);
  const sealed = localStorage.getItem('nss_site_cache') ?? '';
  const back = await loadSiteCache();
  const expired = await (async () => {
    await saveSiteCache({ ...cache, createdAt: Date.now() - 31 * 24 * 3600 * 1000 });
    return loadSiteCache();
  })();
  await saveSiteCache(cache);
  deleteSiteCache();
  const gone = await loadSiteCache();
  const ok =
    JSON.stringify(back) === JSON.stringify(cache) &&
    !sealed.includes('bbbb') &&
    expired === null &&
    gone === null;
  return {
    name: 'siteCache',
    ok,
    detail: ok ? 'sealed, restored, expired, deleted' : JSON.stringify({ back, expired, gone }),
  };
}

async function main() {
  const results: Check[] = [];
  for (const check of [
    derivation,
    async () => buffer(),
    evolu,
    globalList,
    syncedApps,
    noPersistPrompt,
    siteCache,
  ]) {
    try {
      results.push(await check());
    } catch (e) {
      results.push({
        name: check.name || 'check',
        ok: false,
        detail: String((e as Error)?.message ?? e),
      });
    }
  }
  (window as { selftest?: Check[] }).selftest = results;
  const root = document.getElementById('root');
  if (root) root.textContent = JSON.stringify(results, null, 2);
}

void main();
