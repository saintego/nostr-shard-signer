// A fake world for the global sign-in's flow tests: relays, Evolu copies and
// lists in memory (popupFlow.spec.ts, inlineSignIn.spec.ts).
import type { Event, Filter } from 'nostr-tools';
import { generateSecretKey } from 'nostr-tools/pure';
import type { EnvelopeCopies } from '../bunker/src/lib/envelopeStore.ts';
import {
  buildList,
  type GlobalList,
  type IdentityRow,
  type LinkRecord,
  newestLinks,
  type PairingRow,
} from '../bunker/src/lib/globalListModel.ts';
import type { FlowDeps } from '../bunker/src/lib/popupFlow.ts';
import type { PopupLogin } from '../bunker/src/lib/popupLogin.ts';

export const SITE = 'https://app.example';
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

export function world() {
  const relay: Event[] = [];
  const copies = new Map<string, string[]>();
  const lists = new Map<
    string,
    { rows: IdentityRow[]; pairs: PairingRow[]; links: LinkRecord[] }
  >();
  let answered = true;
  const deps: FlowDeps = {
    query: async (f: Filter) => {
      if (!answered) return null;
      return relay.filter(
        (e) =>
          (!f.kinds || f.kinds.includes(e.kind)) &&
          (!f.authors || f.authors.includes(e.pubkey)) &&
          (!f['#d'] || e.tags.some((t) => t[0] === 'd' && f['#d']?.includes(t[1] ?? '')))
      );
    },
    publish: async (events) => {
      relay.push(...events);
    },
    openCopies: async (owner): Promise<EnvelopeCopies> => ({
      synced: answered,
      contents: async () => copies.get(hex(owner)) ?? [],
      write: async (c) => {
        copies.set(hex(owner), [...(copies.get(hex(owner)) ?? []), c]);
      },
      close: async () => {},
    }),
    openList: async (root): Promise<GlobalList> => {
      const st = lists.get(hex(root)) ?? { rows: [], pairs: [], links: [] };
      lists.set(hex(root), st);
      return {
        synced: answered ? 'Synced' : 'Offline',
        load: async () => buildList(st.rows, st.pairs),
        addDerived: async (index, pubkey, createdOn, label) => {
          st.rows.push({ pubkey, derivationIndex: index, label, createdOn, usedElsewhere: null });
        },
        addStored: async () => {},
        pair: async (pubkey, origin) => {
          st.pairs.push({ origin, identityPubkey: pubkey });
        },
        unpair: async () => {},
        links: async () => newestLinks(st.links),
        saveLink: async (l) => {
          st.links.push(l);
        },
        markUsedElsewhere: async () => {},
        close: async () => 'Synced',
      };
    },
    now: () => 1_700_000_000,
  };
  return {
    deps,
    relay,
    offline: () => (answered = false),
    /** Every list forgets its link records (a lost or half-written list, #142). */
    dropLinks: () => {
      for (const st of lists.values()) st.links = [];
    },
  };
}

export const login = (provider: string, masked: string): PopupLogin => ({
  login: { key: generateSecretKey(), provider, userId: `${provider}:${masked}`, masked },
  profile: null,
});
