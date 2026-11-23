// The signer's Evolu databases (#73 D9, D11; #86). Each store has its own
// Evolu owner, from a key derived for it (derive.ts), so a store's data syncs
// end-to-end encrypted and only that key opens it:
//   - "global": the global list (identities, paired sites, labels, stored
//     identities); owner from the root (#80, #84);
//   - "site": one site's store (its identities' keys, settings, marker); owner
//     from that site's store key (#81);
//   - "settings": Amber and extension users' synced settings; owner from
//     HKDF(M, settings) (#88).
// The tables are the v1 model; Evolu adds columns and tables without a
// migration, so later steps extend them.
//
// Import lib/bufferBase64url.ts before this module (main.tsx does).

import {
  AppName,
  createAppOwner,
  createEvolu,
  DateIso,
  String as EvoluString,
  id,
  type Name,
  NonEmptyTrimmedString100,
  NonNegativeInt,
  nullOr,
  OwnerSecret,
} from '@evolu/common';
import {
  type OwnerId,
  type OwnerSyncStatus,
  syncStateToOwnerSyncStatus,
} from '@evolu/common/local-first';
import { createEvoluDeps, createRun } from '@evolu/web';

const IdentityId = id('Identity');
const PairedSiteId = id('PairedSite');
const SiteIdentityId = id('SiteIdentity');
const SettingId = id('Setting');
const LinkId = id('Link');
const EnvelopeId = id('Envelope');

/** The global list. */
export const globalSchema = {
  identity: {
    id: IdentityId,
    /** Derivation index (derived identities); null for stored ones. */
    derivationIndex: nullOr(NonNegativeInt),
    /** Hex secret key of a stored identity (imported or brought over, D9); null for derived ones. */
    storedKey: nullOr(EvoluString),
    pubkey: NonEmptyTrimmedString100,
    label: nullOr(EvoluString),
    /** The site where it was created, as a canonical origin. */
    createdOn: nullOr(EvoluString),
    /** Set when exported, brought over or imported (D13). */
    usedElsewhere: nullOr(DateIso),
  },
  pairedSite: {
    id: PairedSiteId,
    origin: NonEmptyTrimmedString100,
    identityPubkey: NonEmptyTrimmedString100,
  },
  /**
   * A linked sign-in (D25, #98): what unlinking needs without that login
   * (its pointer key and envelope owner, hex), and what the UI shows.
   */
  link: {
    id: LinkId,
    provider: NonEmptyTrimmedString100,
    masked: EvoluString,
    /** 'full' or 'restricted' (JSON list of pubkeys for restricted). */
    scope: EvoluString,
    pointerPubkey: NonEmptyTrimmedString100,
    pointerKey: EvoluString,
    pointerD: EvoluString,
    envelopeOwner: EvoluString,
    version: NonNegativeInt,
    /** The last pointer event (JSON), re-sent at each global sign-in (review 8, item 9). */
    pointerEvent: EvoluString,
    linkedAt: DateIso,
    unlinkedAt: nullOr(DateIso),
  },
} as const;

/** A linked sign-in's own database: copies of its envelope (D25), under an owner only it (and the root) can open. */
export const envelopeSchema = {
  envelope: { id: EnvelopeId, content: EvoluString },
} as const;

/** One site's store. */
export const siteSchema = {
  siteIdentity: {
    id: SiteIdentityId,
    pubkey: NonEmptyTrimmedString100,
    /** Hex secret key of this identity, for this site only. */
    secretKey: EvoluString,
  },
  setting: { id: SettingId, name: NonEmptyTrimmedString100, value: EvoluString },
} as const;

/** Amber and extension users' synced settings. */
export const settingsSchema = {
  setting: { id: SettingId, name: NonEmptyTrimmedString100, value: EvoluString },
} as const;

// Never ask the browser for persistent storage (#101): Firefox shows a prompt
// for it, in the signer's own windows and pages too, and what the signer keeps
// is synced or a cache (data stays without it: checks C8 of #75).
const deps = createEvoluDeps({ requestPersistentStorage: () => {} });
const run = createRun(deps);

/**
 * Resolves when an owner's relay reports it reconciled ("Synced"), or with
 * the last status after `timeoutMs` (offline, error, still syncing). The popup
 * waits for this before reading the global list on a new device.
 */
export function waitForSync(
  name: Name,
  ownerId: OwnerId,
  timeoutMs: number
): Promise<OwnerSyncStatus['type']> {
  return new Promise((resolve) => {
    const status = () => syncStateToOwnerSyncStatus(deps.syncState.get(), name, ownerId).type;
    if (status() === 'Synced') return resolve('Synced');
    const timer = setTimeout(() => {
      unsubscribe();
      resolve(status());
    }, timeoutMs);
    const unsubscribe = deps.syncState.subscribe(() => {
      if (status() !== 'Synced') return;
      clearTimeout(timer);
      unsubscribe();
      resolve('Synced');
    });
  });
}

/** Evolu's own errors (database refused, worker failed), for the UI to show. */
export const onEvoluError = (listener: (error: unknown) => void): (() => void) =>
  deps.evoluError.subscribe(() => {
    const e = deps.evoluError.get();
    if (e !== null) listener(e);
  });

/** Options for every store. `sync: false` keeps it on this device (tests, until a relay is chosen). */
export interface StoreOptions {
  readonly sync?: boolean;
  /**
   * Keep nothing on this device: the popup opens the global list this way, so
   * the signer's top-level storage holds nothing long-lived (#73 D23).
   */
  readonly memoryOnly?: boolean;
}

/**
 * The test build of the whole sign-in only (VITE_FAKE_W3A, #127): no sync
 * server, and stores on the device instead of in memory, so the widget and the
 * sign-in window (on one origin in those tests) share them. Real users always
 * go through memory and sync; that part isn't covered there.
 */
export const OFFLINE_TEST_STORES = import.meta.env?.VITE_FAKE_W3A === '1';

const config = (name: string, ownerSecret: Uint8Array, options: StoreOptions) => ({
  appName: AppName.orThrow(`nss-${name}`),
  appOwner: createAppOwner(OwnerSecret.orThrow(ownerSecret)),
  // Don't reload the page when a database is deleted (Evolu's default).
  onDatabaseDeleted: () => {},
  ...(options.sync === false || OFFLINE_TEST_STORES ? { transports: [] } : {}),
  ...(options.memoryOnly && !OFFLINE_TEST_STORES ? { memoryOnly: true } : {}),
});

// `ownerSecret` is the 32-byte key derived for the store (see the top).
export const openGlobalStore = (ownerSecret: Uint8Array, options: StoreOptions = {}) =>
  run.ok(createEvolu(globalSchema, config('global', ownerSecret, options)));

export const openSiteStore = (ownerSecret: Uint8Array, options: StoreOptions = {}) =>
  run.ok(createEvolu(siteSchema, config('site', ownerSecret, options)));

export const openEnvelopeStore = (ownerSecret: Uint8Array, options: StoreOptions = {}) =>
  run.ok(createEvolu(envelopeSchema, config('envelope', ownerSecret, options)));

export const openSettingsStore = (ownerSecret: Uint8Array, options: StoreOptions = {}) =>
  run.ok(createEvolu(settingsSchema, config('settings', ownerSecret, options)));
