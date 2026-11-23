import { npubEncode } from 'nostr-tools/nip19';
import { useEffect, useRef, useState } from 'react';
import { type BackupFile, parseBackupFile } from '../lib/backupFile';
import { openGlobalList } from '../lib/globalList';
import type { GlobalList, ListedIdentity } from '../lib/globalListModel';
import { format } from '../lib/i18n';
import { needsPassword, parseMasterKey } from '../lib/masterKey';
import { restoreRefusal } from '../lib/restore';
import {
  bunkerDecrypter,
  extension,
  extensionDecrypter,
  type Unlocked,
  unlockFile,
  unlockFileWithRoot,
  unlockWithRoot,
} from '../lib/restoreUnlock';
import { useMessages } from '../lib/useMessages';
import { RestoreIdentities } from './RestoreIdentities';
import { restoreMessages } from './RestoreMessages';
import './WelcomeBack.css';
import './Restore.css';

/**
 * <signer origin>/restore (#73 D10, #87): opened by the user only, never in a
 * frame or a window another page opened. Unlocks the root and lets the user
 * export their identities' keys into another signer.
 */
export function RestoreView() {
  const m = useMessages(restoreMessages);
  const refusal = restoreRefusal(window);
  const [masterKey, setMasterKey] = useState('');
  const [password, setPassword] = useState('');
  const [file, setFile] = useState<BackupFile | null>(null);
  const [bunker, setBunker] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [unlocked, setUnlocked] = useState<Unlocked | null>(null);
  const [identities, setIdentities] = useState<readonly ListedIdentity[]>([]);
  // The global list (Evolu, in memory): names, and marking exports (D9).
  const listRef = useRef<Promise<GlobalList> | null>(null);

  useEffect(() => {
    const wipe = () => {
      unlocked?.root.fill(0);
      void listRef.current?.then((l) => l.close(0));
    };
    window.addEventListener('pagehide', wipe);
    return () => window.removeEventListener('pagehide', wipe);
  }, [unlocked]);

  if (refusal) {
    return (
      <main className="global-popup np-app">
        <h1 className="np-title">{m.title}</h1>
        <p className="np-message np-error">{refusal === 'framed' ? m.framed : m.opened}</p>
      </main>
    );
  }

  const run = async (step: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try {
      await step();
    } catch (e) {
      setError((e as Error)?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const done = (u: Unlocked) => {
    listRef.current = openGlobalList(u.root);
    setUnlocked(u);
    setIdentities(u.identities);
  };

  const root = () => {
    const r = parseMasterKey(masterKey, password);
    if (!r.ok) throw new Error(r.error);
    return r.value;
  };

  const openWithKey = () =>
    run(async () => {
      const r = root();
      if (file) {
        const u = await unlockFileWithRoot(file, r);
        if (!u.ok) throw new Error(u.error);
        return done(u.value);
      }
      const list = await openGlobalList(r);
      const u = await unlockWithRoot(r, await list.load());
      listRef.current = Promise.resolve(list);
      setUnlocked(u);
      setIdentities(u.identities);
    });

  const openWithExtension = () =>
    run(async () => {
      if (!file) return;
      const d = await extensionDecrypter(file);
      if (!d.ok) throw new Error(d.error);
      const u = await unlockFile(file, d.value, true);
      if (!u.ok) throw new Error(u.error);
      done(u.value);
    });

  const openWithBunker = () =>
    run(async () => {
      if (!file) return;
      const d = await bunkerDecrypter(file, bunker);
      if (!d.ok) throw new Error(d.error);
      try {
        const u = await unlockFile(file, d.value.decrypt, true);
        if (!u.ok) throw new Error(u.error);
        done(u.value);
      } finally {
        await d.value.close().catch(() => {});
      }
    });

  const readFile = async (f: File | undefined) => {
    setError('');
    if (!f) return setFile(null);
    const parsed = parseBackupFile(await f.text());
    if (!parsed.ok) return setError(parsed.error);
    setFile(parsed.value);
  };

  const exported = (i: ListedIdentity) => {
    void listRef.current?.then((l) => l.markUsedElsewhere(i.pubkey, i.index)).catch(() => {});
    setIdentities((all) =>
      all.map((x) => (x.pubkey === i.pubkey ? { ...x, usedElsewhere: true } : x))
    );
  };

  return (
    <main className="global-popup restore-page np-app">
      <h1 className="np-title">{m.title}</h1>
      <p>{m.intro}</p>
      <p className="np-message np-info">{m.checkAddress}</p>
      {unlocked ? (
        <>
          {unlocked.signerHeldRoot && <p className="np-message np-warning">{m.removeFromSigner}</p>}
          <RestoreIdentities root={unlocked.root} identities={identities} onExported={exported} />
          <button type="button" className="np-button np-text" onClick={() => location.reload()}>
            {m.startOver}
          </button>
        </>
      ) : (
        <>
          <section className="restore-section">
            <h2 className="np-title">{m.fileTitle}</h2>
            <label className="np-field">
              <span className="np-label">{m.fileField}</span>
              <input
                className="np-input"
                type="file"
                accept="application/json,.json,text/plain,.txt"
                onChange={(e) => void readFile(e.target.files?.[0])}
              />
            </label>
            {file && (
              <p className="np-hint">{format(m.fileFor, { npub: npubEncode(file.rootPubkey) })}</p>
            )}
          </section>
          <section className="restore-section">
            <h2 className="np-title">{m.keyTitle}</h2>
            <label className="np-field">
              <span className="np-label">{m.keyField}</span>
              <input
                className="np-input"
                type="password"
                autoComplete="off"
                value={masterKey}
                onChange={(e) => setMasterKey(e.target.value)}
              />
            </label>
            {needsPassword(masterKey) && (
              <label className="np-field">
                <span className="np-label">{m.password}</span>
                <input
                  className="np-input"
                  type="password"
                  autoComplete="off"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </label>
            )}
            <button
              type="button"
              className="np-button np-filled"
              disabled={busy || !masterKey}
              onClick={() => void openWithKey()}
            >
              {file ? m.unlockKey : m.open}
            </button>
          </section>
          {file && (
            <section className="restore-section">
              {extension() && (
                <button
                  type="button"
                  className="np-button np-tonal"
                  disabled={busy}
                  onClick={() => void openWithExtension()}
                >
                  {m.unlockExtension}
                </button>
              )}
              <label className="np-field">
                <span className="np-label">{m.bunkerField}</span>
                <input
                  className="np-input"
                  value={bunker}
                  onChange={(e) => setBunker(e.target.value)}
                  placeholder="bunker://…"
                />
              </label>
              <button
                type="button"
                className="np-button np-outlined"
                disabled={busy || !bunker}
                onClick={() => void openWithBunker()}
              >
                {m.unlockBunker}
              </button>
            </section>
          )}
          {busy && <p className="np-loading">{m.working}</p>}
          {error && <p className="np-message np-error">{error}</p>}
        </>
      )}
    </main>
  );
}
