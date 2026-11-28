// The account's linked sign-ins (D25, #98), opened with the account: their
// records, linking and unlinking, a link listed again (#142), and what the
// widget keeps of them (#138). Split out of globalAccount.ts.

import { deriveIdentity } from './derive';
import { pointerAddress } from './envelope';
import type { AccountDeps, GlobalAccount } from './globalAccount';
import type { GlobalList, LinkRecord, ListedIdentity } from './globalListModel';
import {
  type LinkingDeps,
  type LinkScope,
  type Login,
  rebuiltLinkRecord,
  sealLink,
  storedPointers,
  unlinkRecord,
} from './linking';

const toHexKey = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHexKey = (h: string) =>
  Uint8Array.from(h.match(/../g) ?? [], (x) => Number.parseInt(x, 16));

export async function openAccountLinks(
  root: Uint8Array,
  list: GlobalList,
  deps: AccountDeps,
  now: () => number,
  listed: () => readonly ListedIdentity[]
) {
  let links = await list.links();
  const linkingDeps = (): LinkingDeps => {
    if (!deps.openCopies) throw new Error('Linking needs the envelope store');
    return {
      query: deps.query,
      publish: deps.publish,
      openCopies: deps.openCopies,
      openList: deps.openList,
      now,
      ...(deps.defer ? { defer: deps.defer } : {}),
    };
  };
  /** The identities a restricted link opens, with their keys (derived, or stored). */
  const linkScope = async (scope: 'full' | readonly string[]): Promise<LinkScope> => {
    if (scope === 'full') return { kind: 'full' };
    const identities = [];
    for (const pubkey of scope) {
      const i = listed().find((x) => x.pubkey === pubkey);
      if (!i) throw new Error('Not an identity of this account');
      const key = i.storedKey ? fromHexKey(i.storedKey) : await deriveIdentity(root, i.index ?? 0);
      identities.push({ secretKey: toHexKey(key), pubkey, index: i.index, label: i.label });
      key.fill(0);
    }
    return { kind: 'restricted', identities };
  };
  // Re-send the stored pointers, linked and unlinked (review 8, item 9).
  if (links.length && deps.scope !== 'site')
    void deps.publish(storedPointers(links)).catch(() => {});
  let via = deps.viaPointer ? links.find((l) => l.pointerPubkey === deps.viaPointer) : undefined;
  // A full link that opened the account isn't in the synced list (a link left
  // half-done, or a lost list): list it again, so it can be seen and unlinked
  // (#142). Not from an unsynced list, which would add duplicates.
  let relistedLink: GlobalAccount['relistedLink'] = null;
  const listSynced = list.synced === 'Synced' || list.synced === 'NoRelays';
  if (!via && deps.viaLogin && listSynced) {
    const record = await rebuiltLinkRecord(deps.viaLogin.login, deps.viaLogin.version, now());
    await list.saveLink(record);
    links = await list.links();
    via = links.find((l) => l.pointerPubkey === record.pointerPubkey);
    relistedLink = { provider: record.provider, masked: record.masked };
  }
  // The sign-in's own record was checked (unlinkedVia): the widget keeps no others (#138).
  if (deps.scope === 'site') links = [];

  return {
    get all(): readonly LinkRecord[] {
      return links;
    },
    unlinkedVia: via?.unlinkedAt ?? null,
    relistedLink,
    /** Links `login`; a restricted link marks its identities used elsewhere (D13). */
    link: async (login: Login, scope: 'full' | readonly string[], after = 0) => {
      if (!deps.primary) throw new Error('The account’s first sign-in isn’t known here');
      const { pubkey } = await pointerAddress(login.key);
      const previous = links.find((l) => l.pointerPubkey === pubkey);
      const record = await sealLink(
        root,
        login,
        await linkScope(scope),
        deps.primary,
        Math.max(previous?.version ?? 0, after) + 1,
        linkingDeps()
      );
      await list.saveLink(record);
      // A restricted link hands these keys to another sign-in: rewrites of
      // their data ask from now on (D13, decided for #145).
      if (scope !== 'full')
        for (const pk of scope)
          await list.markUsedElsewhere(
            pk,
            listed().find((i) => i.pubkey === pk)?.index ?? null
          );
      links = await list.links();
    },
    unlink: async (pointerPubkey: string) => {
      const record = links.find((l) => l.pointerPubkey === pointerPubkey && !l.unlinkedAt);
      if (!record) return;
      await list.saveLink(await unlinkRecord(record, linkingDeps()));
      links = await list.links();
    },
  };
}
