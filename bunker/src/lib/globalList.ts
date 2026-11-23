// The global list (#73 D8, D9, D11; #84): the user's identities, where each
// was created and which sites it's paired with. Readable only with the root,
// so only in the global sign-in popup. The popup opens it in memory (nothing
// kept on the signer's own origin, D23), waits for Evolu to sync, reads it,
// writes the user's choice and waits for that to sync before closing.
//
// The model (pure) is in globalListModel.ts.

import {
  createQueryBuilder,
  DateIso,
  NonEmptyTrimmedString100,
  NonNegativeInt,
  sqliteTrue,
} from '@evolu/common';
import { canonicalOrigin, deriveGlobalStoreKey } from './derive';
import { globalSchema, openGlobalStore, waitForSync } from './evoluStore';
import {
  buildList,
  type GlobalList,
  linkFromRow,
  newestLinks,
  type SyncResult,
} from './globalListModel';

// ── Evolu ─────────────────────────────────────────────────────────────────────

const query = createQueryBuilder(globalSchema);
const identitiesQuery = query((db) =>
  db
    .selectFrom('identity')
    .select(['id', 'pubkey', 'derivationIndex', 'label', 'createdOn', 'usedElsewhere'])
    .where('isDeleted', 'is not', sqliteTrue)
);
const pairingsQuery = query((db) =>
  db
    .selectFrom('pairedSite')
    .select(['id', 'origin', 'identityPubkey'])
    .where('isDeleted', 'is not', sqliteTrue)
);

const linksQuery = query((db) =>
  db
    .selectFrom('link')
    .select([
      'id',
      'provider',
      'masked',
      'scope',
      'pointerPubkey',
      'pointerKey',
      'pointerD',
      'envelopeOwner',
      'version',
      'pointerEvent',
      'linkedAt',
      'unlinkedAt',
    ])
    .where('isDeleted', 'is not', sqliteTrue)
);

/**
 * How long opening waits for the list to sync (#110). Past it the window goes
 * on with what's on the device and the relays (`synced` says so); waiting
 * longer made every sign-in slow.
 */
const OPEN_SYNC_MS = 2500;
/** How long closing waits for writes to reach Evolu's relay. */
const CLOSE_SYNC_MS = 8000;

const done = (run: (onComplete: () => void) => void) =>
  new Promise<void>((resolve) => run(resolve));

/** Opens the global list for `root`, in memory, and waits for its first sync. */
export async function openGlobalList(
  root: Uint8Array,
  options: { sync?: boolean } = {}
): Promise<GlobalList> {
  const ownerSecret = await deriveGlobalStoreKey(root);
  const evolu = await openGlobalStore(ownerSecret, {
    memoryOnly: true,
    ...(options.sync === false ? { sync: false } : {}),
  });
  ownerSecret.fill(0);
  const sync = (ms: number) =>
    options.sync === false
      ? Promise.resolve<SyncResult>('NoRelays')
      : waitForSync(evolu.name, evolu.appOwner.id, ms);
  const synced = await sync(OPEN_SYNC_MS);

  const load = async () => {
    const [ids, pairs] = await Promise.all([
      evolu.loadQuery(identitiesQuery),
      evolu.loadQuery(pairingsQuery),
    ]);
    return buildList(ids, pairs);
  };

  return {
    synced,
    load,
    addDerived: (index, pubkey, createdOn, label) =>
      done((onComplete) =>
        evolu.insert(
          'identity',
          {
            derivationIndex: NonNegativeInt.orThrow(index),
            storedKey: null,
            pubkey: NonEmptyTrimmedString100.orThrow(pubkey),
            label,
            createdOn: canonicalOrigin(createdOn),
            usedElsewhere: null,
          },
          { onComplete }
        )
      ),
    addStored: (secretKeyHex, pubkey, createdOn, label) =>
      done((onComplete) =>
        evolu.insert(
          'identity',
          {
            derivationIndex: null,
            storedKey: secretKeyHex,
            pubkey: NonEmptyTrimmedString100.orThrow(pubkey),
            label,
            createdOn: canonicalOrigin(createdOn),
            usedElsewhere: DateIso.orThrow(new Date().toISOString()),
          },
          { onComplete }
        )
      ),
    pair: async (pubkey, origin) => {
      const o = canonicalOrigin(origin);
      const pairs = await evolu.loadQuery(pairingsQuery);
      if (pairs.some((p) => p.origin === o && p.identityPubkey === pubkey)) return;
      await done((onComplete) =>
        evolu.insert(
          'pairedSite',
          {
            origin: NonEmptyTrimmedString100.orThrow(o),
            identityPubkey: NonEmptyTrimmedString100.orThrow(pubkey),
          },
          { onComplete }
        )
      );
    },
    unpair: async (pubkey, origin) => {
      const o = canonicalOrigin(origin);
      const pairs = (await evolu.loadQuery(pairingsQuery)).filter(
        (p) => p.origin === o && p.identityPubkey === pubkey
      );
      for (const p of pairs)
        await done((onComplete) =>
          evolu.update('pairedSite', { id: p.id, isDeleted: sqliteTrue }, { onComplete })
        );
    },
    links: async () => newestLinks((await evolu.loadQuery(linksQuery)).map(linkFromRow)),
    saveLink: (link) =>
      done((onComplete) =>
        evolu.insert(
          'link',
          {
            provider: NonEmptyTrimmedString100.orThrow(link.provider),
            masked: link.masked,
            scope: link.scope === 'full' ? 'full' : JSON.stringify(link.scope),
            pointerPubkey: NonEmptyTrimmedString100.orThrow(link.pointerPubkey),
            pointerKey: link.pointerKey,
            pointerD: link.pointerD,
            envelopeOwner: link.envelopeOwner,
            version: NonNegativeInt.orThrow(link.version),
            pointerEvent: link.pointerEvent,
            linkedAt: DateIso.orThrow(link.linkedAt),
            unlinkedAt: link.unlinkedAt ? DateIso.orThrow(link.unlinkedAt) : null,
          },
          { onComplete }
        )
      ),
    markUsedElsewhere: async (pubkey, index) => {
      const usedElsewhere = DateIso.orThrow(new Date().toISOString());
      const rows = (await evolu.loadQuery(identitiesQuery)).filter((r) => r.pubkey === pubkey);
      if (rows.length === 0 && index !== null) {
        await done((onComplete) =>
          evolu.insert(
            'identity',
            {
              derivationIndex: NonNegativeInt.orThrow(index),
              storedKey: null,
              pubkey: NonEmptyTrimmedString100.orThrow(pubkey),
              label: null,
              createdOn: null,
              usedElsewhere,
            },
            { onComplete }
          )
        );
      }
      for (const r of rows)
        await done((onComplete) =>
          evolu.update('identity', { id: r.id, usedElsewhere }, { onComplete })
        );
    },
    close: async (timeoutMs = CLOSE_SYNC_MS) => {
      const result: SyncResult = timeoutMs > 0 ? await sync(timeoutMs) : 'Syncing';
      await evolu[Symbol.asyncDispose]();
      return result;
    },
  };
}
