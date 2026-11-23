// The allowed-apps list for Evolustr app keys, kept on the device and synced
// (#88): how the device's list and the synced rows combine. Pure.

/** One synced row: an app, allowed or forgotten (a deleted row). */
export interface AppRow {
  readonly appId: string;
  readonly deleted: boolean;
}

/**
 * The combined list, and what the device adds to the synced rows. An app
 * forgotten on another device (a deleted row) leaves this device's list too;
 * an app only this device knows is added to the synced rows.
 */
export function mergeAllowedApps(
  local: readonly string[],
  rows: readonly AppRow[]
): { readonly apps: string[]; readonly toAdd: string[] } {
  const known = new Map(rows.map((r) => [r.appId, r.deleted]));
  const synced = rows.filter((r) => !r.deleted).map((r) => r.appId);
  const toAdd = local.filter((a) => !known.has(a));
  const apps = [...new Set([...synced, ...toAdd])];
  return { apps, toAdd };
}
