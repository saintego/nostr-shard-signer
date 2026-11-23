// The apps allowed to use Evolustr app keys (#88): kept on the device as
// before, and for Amber and extension users also synced in Evolu under
// Evolustr's host secret, so the list comes back on another device. A hook so
// App.tsx doesn't grow (AGENTS.md, Files).
import { useCallback, useEffect, useRef, useState } from 'react';
import { mergeAllowedApps } from './lib/allowedAppsModel';
import { type EvolustrSigner, loadAllowedApps, saveAllowedApps } from './lib/evolustr';
import { openSyncedApps, SETTINGS_LABEL, type SyncedApps } from './lib/syncedApps';

/** The signer itself, as the caller of its own status check. */
const selfCaller = { identity: 'verified' as const, origin: location.origin };

/** Apps allowed under the earlier host secrets, after a key replacement (evolustr #59). */
async function earlierApps(signer: EvolustrSigner): Promise<string[]> {
  const previous = await signer.getPreviousHostSecrets(SETTINGS_LABEL);
  const apps: string[] = [];
  for (const old of previous.ok ? previous.value : []) {
    const store = await openSyncedApps(old);
    apps.push(...(await store.rows()).filter((r) => !r.deleted).map((r) => r.appId));
    void store.close();
  }
  return apps;
}

interface Deps {
  /** The signed-in user, or null. */
  readonly pubkey: string | null;
  /** Synced only for Amber and extension users (#73 D20); others keep the device list. */
  readonly synced: boolean;
  readonly evolustr: () => EvolustrSigner | null;
}

export function useSyncedApps({ pubkey, synced, evolustr }: Deps) {
  const [apps, setApps] = useState<string[]>([]);
  const storeRef = useRef<SyncedApps | null>(null);

  useEffect(() => {
    setApps(pubkey ? loadAllowedApps(pubkey) : []);
    return () => {
      void storeRef.current?.close();
      storeRef.current = null;
    };
  }, [pubkey]);

  const keep = useCallback(
    (next: string[]) => {
      if (!pubkey) return;
      saveAllowedApps(pubkey, next);
      setApps(next);
    },
    [pubkey]
  );

  /**
   * Opens the synced list once Evolustr's M is unlocked (never a passkey
   * prompt for it), merges it with the device's, and keeps both. After a key
   * replacement, lists kept under the earlier host secrets join in.
   */
  const sync = useCallback(async () => {
    const signer = evolustr();
    if (!pubkey || !synced || storeRef.current || !signer) return;
    const caps = await signer.capabilities(selfCaller);
    if (!caps.ok || !caps.value.ready) return;
    const secret = await signer.getHostSecret(SETTINGS_LABEL);
    if (!secret.ok || storeRef.current) return;
    const store = await openSyncedApps(secret.value);
    storeRef.current = store;
    const earlier = await earlierApps(signer);
    const merged = mergeAllowedApps([...loadAllowedApps(pubkey), ...earlier], await store.rows());
    for (const appId of merged.toAdd) await store.allow(appId);
    keep(merged.apps);
  }, [pubkey, synced, evolustr, keep]);

  /** The user allowed an app: on the device, and synced (M is unlocked by then). */
  const allow = useCallback(
    async (appId: string) => {
      if (!pubkey) return;
      const now = loadAllowedApps(pubkey);
      if (!now.includes(appId)) keep([...now, appId]);
      await storeRef.current?.allow(appId);
      await sync();
    },
    [pubkey, keep, sync]
  );

  /** "Forget": asks again next time, on every device. */
  const forget = useCallback(
    async (appId: string) => {
      if (!pubkey) return;
      keep(loadAllowedApps(pubkey).filter((a) => a !== appId));
      await storeRef.current?.forget(appId);
    },
    [pubkey, keep]
  );

  return { apps, allow, forget, sync };
}
