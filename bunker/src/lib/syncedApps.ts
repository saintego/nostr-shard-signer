// The allowed-apps list in Evolu (#73 D20, #88), for Amber and extension
// users: its owner comes from Evolustr's host secret for
// "nostr-shard-signer/v1/settings" (derived from M), so the list comes back on
// another device once the signer passkey unlocks M. One row per app, with a
// fixed id, so devices merge per app (allowedAppsModel.ts).

import {
  createIdFromString,
  createQueryBuilder,
  String as EvoluString,
  NonEmptyTrimmedString100,
  sqliteTrue,
} from '@evolu/common';
import type { AppRow } from './allowedAppsModel';
import { OFFLINE_TEST_STORES, openSettingsStore, settingsSchema, waitForSync } from './evoluStore';

/** The host secret's label: the signer's own data, apart from every app's key. */
export const SETTINGS_LABEL = 'nostr-shard-signer/v1/settings';

const ROW_NAME = NonEmptyTrimmedString100.orThrow('allowed-app');
/** How long opening waits for the rows to sync. */
const SYNC_MS = 8000;

const query = createQueryBuilder(settingsSchema);
const allRows = query((db) =>
  db.selectFrom('setting').select(['id', 'name', 'value', 'isDeleted']).where('name', '=', ROW_NAME)
);

const rowId = (appId: string) => createIdFromString<'Setting'>(`${ROW_NAME}:${appId}`);

export interface SyncedApps {
  readonly rows: () => Promise<AppRow[]>;
  readonly allow: (appId: string) => Promise<void>;
  readonly forget: (appId: string) => Promise<void>;
  readonly close: () => Promise<void>;
}

export async function openSyncedApps(
  secret: Uint8Array,
  options: { sync?: boolean } = {}
): Promise<SyncedApps> {
  const evolu = await openSettingsStore(secret, options.sync === false ? { sync: false } : {});
  const syncing = options.sync !== false && !OFFLINE_TEST_STORES;
  if (syncing) await waitForSync(evolu.name, evolu.appOwner.id, SYNC_MS);
  const write = (appId: string, deleted: boolean) =>
    new Promise<void>((resolve) =>
      evolu.upsert(
        'setting',
        {
          id: rowId(appId),
          name: ROW_NAME,
          value: EvoluString.orThrow(appId),
          ...(deleted ? { isDeleted: sqliteTrue } : {}),
        },
        { onComplete: () => resolve() }
      )
    );
  return {
    rows: async () =>
      (await evolu.loadQuery(allRows))
        .filter((r) => typeof r.value === 'string')
        .map((r) => ({ appId: r.value as string, deleted: r.isDeleted === sqliteTrue })),
    allow: (appId) => write(appId, false),
    forget: (appId) => write(appId, true),
    close: async () => {
      if (syncing) await waitForSync(evolu.name, evolu.appOwner.id, SYNC_MS);
      await evolu[Symbol.asyncDispose]();
    },
  };
}
