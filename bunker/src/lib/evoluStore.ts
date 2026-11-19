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
  id,
  NonEmptyTrimmedString100,
  NonNegativeInt,
  nullOr,
  OwnerSecret,
  String as EvoluString,
} from '@evolu/common';
import { createEvoluDeps, createRun } from '@evolu/web';

const IdentityId = id('Identity');
const PairedSiteId = id('PairedSite');
const SiteIdentityId = id('SiteIdentity');
const SettingId = id('Setting');

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

const deps = createEvoluDeps();
const run = createRun(deps);

/** Evolu's own errors (database refused, worker failed), for the UI to show. */
export const onEvoluError = (listener: (error: unknown) => void): (() => void) =>
  deps.evoluError.subscribe(() => {
    const e = deps.evoluError.get();
    if (e !== null) listener(e);
  });

/** Options for every store. `sync: false` keeps it on this device (tests, until a relay is chosen). */
export interface StoreOptions {
  readonly sync?: boolean;
}

const config = (name: string, ownerSecret: Uint8Array, options: StoreOptions) => ({
  appName: AppName.orThrow(`nss-${name}`),
  appOwner: createAppOwner(OwnerSecret.orThrow(ownerSecret)),
  // Don't reload the page when a database is deleted (Evolu's default).
  onDatabaseDeleted: () => {},
  ...(options.sync === false ? { transports: [] } : {}),
});

// `ownerSecret` is the 32-byte key derived for the store (see the top).
export const openGlobalStore = (ownerSecret: Uint8Array, options: StoreOptions = {}) =>
  run.ok(createEvolu(globalSchema, config('global', ownerSecret, options)));

export const openSiteStore = (ownerSecret: Uint8Array, options: StoreOptions = {}) =>
  run.ok(createEvolu(siteSchema, config('site', ownerSecret, options)));

export const openSettingsStore = (ownerSecret: Uint8Array, options: StoreOptions = {}) =>
  run.ok(createEvolu(settingsSchema, config('settings', ownerSecret, options)));
