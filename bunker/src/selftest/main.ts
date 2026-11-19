// Self-test of the production build setup (#86, review 7 of #73): the same Vite
// config and polyfills as the signer, so the derivation vectors, the patched
// Buffer and Evolu are checked as they run in the shipped bundle, not only as
// sources. Not deployed; tests/selftest.spec.js loads it and reads
// window.selftest.

import '../lib/bufferBase64url';
import { getPublicKey } from 'nostr-tools/pure';
import { deriveIdentity, deriveRoot } from '../lib/derive';
import vectors from '../lib/derive.vectors.json';
import { Buffer as PolyBuffer } from 'buffer';

// The worst case for Evolu: a global Buffer (the polyfill's, as Web3Auth's code
// puts in place in the signer) exists before Evolu loads, so Evolu uses it with
// "base64url". Evolu is imported only after this, below.
const g = globalThis as { Buffer?: unknown };
g.Buffer ??= PolyBuffer;

interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (s: string) => new Uint8Array((s.match(/../g) ?? []).map((h) => Number.parseInt(h, 16)));

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
  const ok = url === '-_8APj8' && hex(back) === hex(bytes) && plain === '+/8APj8=' && B.from('ab', 'hex')[0] === 0xab;
  return { name: 'buffer', ok, detail: `${url} ${plain}` };
}

async function evolu(): Promise<Check> {
  const { openSiteStore, siteSchema } = await import('../lib/evoluStore');
  const { createQueryBuilder, NonEmptyTrimmedString100 } = await import('@evolu/common');
  const store = await openSiteStore(crypto.getRandomValues(new Uint8Array(32)), { sync: false });
  await new Promise<void>((resolve) => {
    store.insert('setting', { name: NonEmptyTrimmedString100.orThrow('selftest'), value: 'ok' }, { onComplete: resolve });
  });
  const createQuery = createQueryBuilder(siteSchema);
  const rows = await store.loadQuery(createQuery((db) => db.selectFrom('setting').select(['name', 'value'])));
  const ok = rows.some((r) => r.name === 'selftest' && r.value === 'ok');
  return { name: 'evolu', ok, detail: `${rows.length} rows` };
}

async function main() {
  const results: Check[] = [];
  for (const check of [derivation, async () => buffer(), evolu]) {
    try {
      results.push(await check());
    } catch (e) {
      results.push({ name: check.name || 'check', ok: false, detail: String((e as Error)?.message ?? e) });
    }
  }
  (window as { selftest?: Check[] }).selftest = results;
  const root = document.getElementById('root');
  if (root) root.textContent = JSON.stringify(results, null, 2);
}

void main();
