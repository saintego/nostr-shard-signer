// The sign-in window's writes (#110): relay events and Evolu syncs run in the
// background, and the window waits for them only before it closes.
import type { Event } from 'nostr-tools';
import { backgroundWrites } from './backgroundWrites';
import { flowDeps } from './flowDeps';
import type { GlobalOptions } from './globalPopup';
import { publishToSignerRelays } from './relayPublish';

export const writes = backgroundWrites<Event>(publishToSignerRelays);

/** The longest the window stays open for unfinished writes after it's done. */
const WRITES_MAX_MS = 20000;

/** Closes the window once its writes are sent (or after WRITES_MAX_MS), `ms` after done at least. */
export const closeAfterWrites = (ms: number) =>
  void Promise.all([writes.settled(WRITES_MAX_MS), new Promise((r) => setTimeout(r, ms))]).then(
    () => window.close()
  );

/** Where the account reads and writes, and this site login's marker address (lib/flowDeps.ts). */
export const depsFor = (options: GlobalOptions) => flowDeps(writes, options.markerAddress);
