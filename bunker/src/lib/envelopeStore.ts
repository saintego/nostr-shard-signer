// A linked sign-in's own Evolu database (#73 D25, #98): copies of its
// envelope, under an owner derived from that login (or kept under the root,
// for unlinking). Opened in memory in the sign-in popup, like the global list.

import { createQueryBuilder, sqliteTrue } from '@evolu/common';
import { envelopeSchema, openEnvelopeStore, waitForSync } from './evoluStore';

export interface EnvelopeCopies {
  /** False when Evolu didn't sync: a copy may be missing. */
  readonly synced: boolean;
  readonly contents: () => Promise<string[]>;
  readonly write: (content: string) => Promise<void>;
  /** Waits up to `timeoutMs` for writes to sync (0: only read here), then closes. */
  readonly close: (timeoutMs?: number) => Promise<void>;
}

const query = createQueryBuilder(envelopeSchema);
const all = query((db) =>
  db.selectFrom('envelope').select(['id', 'content']).where('isDeleted', 'is not', sqliteTrue)
);
/** How long opening waits for the relay's copy (#110): past it, the relays' pointer decides. */
const OPEN_SYNC_MS = 2500;
/** How long closing waits for writes to reach Evolu's relay. */
const CLOSE_SYNC_MS = 8000;

export async function openEnvelopeCopies(
  ownerSecret: Uint8Array,
  options: { sync?: boolean } = {}
): Promise<EnvelopeCopies> {
  const evolu = await openEnvelopeStore(ownerSecret, {
    memoryOnly: true,
    ...(options.sync === false ? { sync: false } : {}),
  });
  const sync = (ms: number) =>
    options.sync === false
      ? Promise.resolve('NoRelays')
      : waitForSync(evolu.name, evolu.appOwner.id, ms);
  const synced = (await sync(OPEN_SYNC_MS)) === 'Synced';
  return {
    synced,
    contents: async () =>
      (await evolu.loadQuery(all))
        .map((r) => r.content)
        .filter((c): c is string => typeof c === 'string'),
    write: (content) =>
      new Promise<void>((resolve) =>
        evolu.insert('envelope', { content }, { onComplete: () => resolve() })
      ),
    close: async (timeoutMs = CLOSE_SYNC_MS) => {
      if (timeoutMs > 0) await sync(timeoutMs);
      await evolu[Symbol.asyncDispose]();
    },
  };
}
