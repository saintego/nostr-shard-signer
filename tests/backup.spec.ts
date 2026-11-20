// Backup and restore (#73 D10, #87): the master key, the encrypted backup
// file (large ones too), and what /restore derives and refuses.
import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import { decode } from 'nostr-tools/nip19';
import * as nip44 from 'nostr-tools/nip44';
import { getPublicKey } from 'nostr-tools/pure';
import {
  buildBackupFile,
  openBackupFile,
  parseBackupFile,
  withRoot,
} from '../bunker/src/lib/backupFile.ts';
import { deriveRoot } from '../bunker/src/lib/derive.ts';
import type { ListedIdentity } from '../bunker/src/lib/globalListModel.ts';
import {
  exportMasterKey,
  needsPassword,
  parseMasterKey,
  restoreUrl,
} from '../bunker/src/lib/masterKey.ts';
import { exportIdentity, restoredIdentities, restoreRefusal } from '../bunker/src/lib/restore.ts';

const vectors = JSON.parse(
  readFileSync(new URL('../bunker/src/lib/derive.vectors.json', import.meta.url), 'utf8')
);
const v = vectors.vectors[0];
const bytes = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

test('the master key: nsec or NIP-49, and back; mistakes are explained', () => {
  const root = bytes(v.root.secret);
  const plain = exportMasterKey(root);
  expect(plain.startsWith('nsec1')).toBe(true);
  const r1 = parseMasterKey(plain);
  expect(r1.ok && hex(r1.value)).toBe(v.root.secret);
  const locked = exportMasterKey(root, 'correct horse');
  expect(needsPassword(locked)).toBe(true);
  expect(parseMasterKey(locked).ok).toBe(false);
  expect(parseMasterKey(locked, 'wrong').ok).toBe(false);
  const r2 = parseMasterKey(locked, 'correct horse');
  expect(r2.ok && hex(r2.value)).toBe(v.root.secret);
  expect(parseMasterKey('npub1xyz').ok).toBe(false);
  expect(restoreUrl('https://saintego.github.io/nostr-shard-signer/')).toBe(
    'https://saintego.github.io/nostr-shard-signer/restore/'
  );
});

test('a large backup (300 identities on hundreds of sites) round-trips; only the root opens it', async () => {
  const root = await deriveRoot(bytes(v.globalLoginKey));
  const identities: ListedIdentity[] = Array.from({ length: 300 }, (_, i) => ({
    pubkey: i.toString(16).padStart(64, '0'),
    index: i,
    label: `Identity ${i}`,
    createdOn: `https://site${i}.example`,
    usedElsewhere: i % 7 === 0,
    sites: Array.from({ length: 3 }, (_, j) => `https://site${i * 3 + j}.example`),
  }));
  const body = {
    v: 1 as const,
    root: hex(root),
    counter: 300,
    identities,
    createdAt: '2026-11-20T00:00:00.000Z',
  };
  const text = await buildBackupFile(body);
  expect(text).not.toContain('site1.example');
  expect(text).not.toContain(hex(root));
  const file = parseBackupFile(text);
  if (!file.ok) throw new Error(file.error);
  expect(file.value.rootPubkey).toBe(getPublicKey(root));
  const opened = await openBackupFile(file.value, withRoot(root));
  expect(opened.ok && opened.value).toEqual(body);
  // A signer holding the root (an extension) decrypts the same file key.
  const extension = async (sender: string, ct: string) =>
    nip44.decrypt(ct, nip44.getConversationKey(root, sender));
  expect((await openBackupFile(file.value, extension)).ok).toBe(true);
  // Another key doesn't.
  const other = await deriveRoot(bytes(vectors.vectors[1].globalLoginKey));
  const refused = await openBackupFile(file.value, withRoot(other));
  expect(refused.ok).toBe(false);
  // Tampering is caught.
  const tampered = { ...file.value, body: `A${file.value.body.slice(1)}` };
  expect((await openBackupFile(tampered, withRoot(root))).ok).toBe(false);
  expect(parseBackupFile('{"type":"other"}').ok).toBe(false);
});

test('/restore lists every derived identity below the counter, and exports their keys', async () => {
  const root = bytes(v.root.secret);
  const known: ListedIdentity = {
    pubkey: v.identities[1].pubkey,
    index: 1,
    label: 'Work',
    createdOn: 'https://a.example',
    usedElsewhere: false,
    sites: ['https://a.example'],
  };
  const list = await restoredIdentities(root, 3, [known]);
  expect(list.map((i) => i.index)).toEqual([0, 1, 2]);
  expect(list[0]?.pubkey).toBe(v.identities[0].pubkey);
  expect(list[1]?.label).toBe('Work');
  const nsec = await exportIdentity(root, 2);
  const d = decode(nsec);
  expect(d.type === 'nsec' && hex(d.data as Uint8Array)).toBe(v.identities[2].secret);
  expect((await exportIdentity(root, 2, 'pw')).startsWith('ncryptsec1')).toBe(true);
});

test('/restore refuses to run in a frame or in a window another page opened', () => {
  const self = {};
  expect(restoreRefusal({ self, top: self, opener: null })).toBeNull();
  expect(restoreRefusal({ self, top: {}, opener: null })).toBe('framed');
  expect(restoreRefusal({ self, top: self, opener: {} })).toBe('opened');
});
