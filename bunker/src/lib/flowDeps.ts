// Where a global sign-in reads and writes (relays, Evolu): the same for the
// sign-in window and the widget (#122). Writes run in the background (#110).

import type { Event } from 'nostr-tools';
import type { BackgroundWrites } from './backgroundWrites';
import { openEnvelopeCopies } from './envelopeStore';
import { openGlobalList } from './globalList';
import type { FlowDeps } from './popupFlow';
import { queryRelays } from './relayPublish';

export const flowDeps = (writes: BackgroundWrites<Event>, markerAddress?: string): FlowDeps => ({
  openList: (root) => openGlobalList(root),
  openCopies: (owner) => openEnvelopeCopies(owner),
  query: (filter) => queryRelays(filter),
  queryAll: (filter) => queryRelays(filter, undefined, { all: true }), // before counter writes (#140)
  publish: writes.publish,
  defer: writes.track,
  ...(markerAddress ? { markerAddress } : {}),
});
