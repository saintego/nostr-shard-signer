// The /restore page (#73 D10, #87): only in its own tab opened by the user;
// the master key or a backup file gives back the identities, whose keys are
// exported into another signer.
import { readFileSync } from 'node:fs';
import { nsecEncode } from 'nostr-tools/nip19';
import { buildBackupFile } from '../bunker/src/lib/backupFile.ts';
import { BUNKER, blankPage, expect, test } from './fixtures.js';

const vectors = JSON.parse(
  readFileSync(new URL('../bunker/src/lib/derive.vectors.json', import.meta.url), 'utf8')
);
const v = vectors.vectors[0];
const bytes = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));
const RESTORE = `${BUNKER}/restore/`;

test('opened by the user: the master key gives back identity 0, and its key exports', async ({
  page,
}) => {
  await page.goto(RESTORE);
  await expect(page.getByRole('heading', { name: 'Restore your Nostr account' })).toBeVisible();
  await page
    .getByLabel('Master key (nsec1… or ncryptsec1…)')
    .fill(nsecEncode(bytes(v.root.secret)));
  await page.getByRole('button', { name: 'Open' }).click();
  await expect(page.getByRole('heading', { name: 'Your identities' })).toBeVisible({
    timeout: 20000,
  });
  await page.getByRole('button', { name: 'Export this identity’s key' }).first().click();
  await page.getByRole('button', { name: 'Show it without a password' }).click();
  await expect(page.locator('code.backup-key')).toHaveText(
    nsecEncode(bytes(v.identities[0].secret))
  );
});

test('a backup file opens with the master key and lists its identities', async ({ page }) => {
  const identities = [
    {
      pubkey: v.identities[0].pubkey,
      index: 0,
      label: 'Main',
      createdOn: 'https://a.example',
      usedElsewhere: false,
      sites: ['https://a.example'],
    },
    {
      pubkey: v.identities[1].pubkey,
      index: 1,
      label: 'Work',
      createdOn: 'https://b.example',
      usedElsewhere: false,
      sites: ['https://b.example'],
    },
  ];
  const text = await buildBackupFile({
    v: 1,
    root: v.root.secret,
    counter: 2,
    identities,
    createdAt: '2026-11-20T00:00:00.000Z',
  });
  await page.goto(RESTORE);
  await page.getByLabel('Backup file').setInputFiles({
    name: 'backup.json',
    mimeType: 'application/json',
    buffer: Buffer.from(text),
  });
  await expect(page.getByText('This file belongs to the account npub1')).toBeVisible();
  await page
    .getByLabel('Master key (nsec1… or ncryptsec1…)')
    .fill(nsecEncode(bytes(v.root.secret)));
  await page.getByRole('button', { name: 'Open it with the master key above' }).click();
  await expect(page.getByText('Work')).toBeVisible({ timeout: 20000 });
  await expect(page.getByText('Used on b.example')).toBeVisible();
  // Another account's master key doesn't open it.
  await page.goto(RESTORE);
  await page.getByLabel('Backup file').setInputFiles({
    name: 'backup.json',
    mimeType: 'application/json',
    buffer: Buffer.from(text),
  });
  await page
    .getByLabel('Master key (nsec1… or ncryptsec1…)')
    .fill(nsecEncode(bytes(vectors.vectors[1].root.secret)));
  await page.getByRole('button', { name: 'Open it with the master key above' }).click();
  await expect(page.getByText('This key doesn’t open this backup file.')).toBeVisible();
});

test('refuses to run in a frame or in a window another page opened', async ({ page, pages }) => {
  pages.set(
    'signer:/host',
    `<!doctype html><iframe src="${RESTORE}" width="600" height="400"></iframe>`
  );
  await page.goto(`${BUNKER}/host`);
  await expect(
    page.frameLocator('iframe').getByText('This page only works in its own tab')
  ).toBeVisible();

  pages.set('signer:/opener', blankPage);
  await page.goto(`${BUNKER}/opener`);
  const popupOpened = page.waitForEvent('popup');
  await page.evaluate((url) => window.open(url, '_blank'), RESTORE);
  const popup = await popupOpened;
  await expect(popup.getByText('This page was opened by another page.')).toBeVisible();
  await expect(popup.getByLabel('Master key (nsec1… or ncryptsec1…)')).toHaveCount(0);
});
