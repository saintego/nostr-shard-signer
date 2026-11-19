// The device secret (#73 D6, #81): a non-extractable AES-GCM key kept in the
// iframe's IndexedDB. Storage is partitioned per site (C8, C19), so each site
// the signer is embedded in has its own. Non-extractable means scripts can use
// it but never read it; a copy of the disk is another matter (stated in #73's
// claims).

const DB = 'nss-device';
const STORE = 'keys';
const KEY = 'device-secret';

function withStore<T>(mode: IDBTransactionMode, f: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction(STORE, mode);
      const req = f(tx.objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => open.result.close();
    };
  });
}

/** This device's secret for this site, created on first use. */
export async function deviceSecret(): Promise<CryptoKey> {
  const existing = await withStore<CryptoKey | undefined>('readonly', (s) => s.get(KEY));
  if (existing) return existing;
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  await withStore('readwrite', (s) => s.put(key, KEY));
  return key;
}

/** Encrypts with the device secret: 12-byte IV, then the ciphertext. */
export async function sealWithDevice(plain: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await deviceSecret(), plain as BufferSource)
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return out;
}

/** Decrypts what sealWithDevice made; null if it isn't this device's. */
export async function openWithDevice(sealed: Uint8Array): Promise<Uint8Array | null> {
  try {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: sealed.slice(0, 12) as BufferSource },
      await deviceSecret(),
      sealed.slice(12) as BufferSource
    );
    return new Uint8Array(plain);
  } catch {
    return null;
  }
}
