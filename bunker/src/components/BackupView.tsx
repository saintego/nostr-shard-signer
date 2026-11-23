import { useEffect, useState } from 'react';
import type { BackupMethod } from '../lib/backup';
import type { GlobalAccount } from '../lib/globalAccount';
import { format } from '../lib/i18n';
import { useMessages } from '../lib/useMessages';
import { backupMessages } from './BackupMessages';

interface Props {
  readonly account: GlobalAccount;
  /** `<signer origin>/restore/`, shown next to the key so both are written down together. */
  readonly restoreAddress: string;
  /** The user saved a backup: how (for the #37 prompt). */
  readonly onDone: (method: BackupMethod) => void;
  readonly onCancel: () => void;
}

const MIN_PASSWORD = 8;
const fileName = () => `nostr-account-backup-${new Date().toISOString().slice(0, 10)}.json`;

/**
 * Backing up the global account (#73 D10, #87), in the signer's popup: the
 * master key (NIP-49 with a password, or plain) and the encrypted backup file.
 */
export function BackupView({ account, restoreAddress, onDone, onCancel }: Props) {
  const m = useMessages(backupMessages);
  const [password, setPassword] = useState('');
  const [repeat, setRepeat] = useState('');
  const [key, setKey] = useState<{ text: string; method: BackupMethod } | null>(null);
  const [copied, setCopied] = useState(false);
  const [wroteDown, setWroteDown] = useState(false);
  const [fileSaved, setFileSaved] = useState(false);
  const [error, setError] = useState('');

  const show = (withPassword: boolean) => {
    if (withPassword && password !== repeat) return setError(m.mismatch);
    setError('');
    setKey({
      text: account.exportMasterKey(withPassword ? password : undefined),
      method: withPassword ? 'ncryptsec' : 'nsec',
    });
  };

  const download = async () => {
    const blob = new Blob([await account.backupFile()], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = fileName();
    a.click();
    URL.revokeObjectURL(a.href);
    setFileSaved(true);
  };
  // Built ahead, so the share starts in the click (it needs the user's
  // activation), as .txt: Android's share sheet refuses .json files. The button
  // shows only where the browser can share it. /restore takes .txt too.
  const [shareFile, setShareFile] = useState<File | null>(null);
  useEffect(() => {
    let live = true;
    void account.backupFile().then((text) => {
      const name = fileName().replace(/\.json$/, '.txt');
      const file = new File([text], name, { type: 'text/plain' });
      if (live && navigator.canShare?.({ files: [file] })) setShareFile(file);
    });
    return () => {
      live = false;
    };
  }, [account]);
  const canShare = shareFile !== null;
  const share = async () => {
    const file = shareFile;
    if (!file) return;
    try {
      await navigator.share({ files: [file], title: m.fileTitle });
      setFileSaved(true);
    } catch {
      // cancelled
    }
  };

  const done = wroteDown || fileSaved;
  return (
    <section className="welcome-back">
      <h2 className="np-title">{m.title}</h2>
      <p className="np-hint">{m.explain}</p>

      <h3 className="np-label">{m.masterTitle}</h3>
      {key ? (
        <>
          <code className="backup-key">{key.text}</code>
          <button
            type="button"
            className="np-button np-outlined np-small"
            onClick={() => void navigator.clipboard.writeText(key.text).then(() => setCopied(true))}
          >
            {copied ? m.copied : m.copy}
          </button>
          <p className="np-message np-warning">{format(m.label, { restore: restoreAddress })}</p>
          <label className="np-checkbox welcome-profile">
            <input
              type="checkbox"
              checked={wroteDown}
              onChange={(e) => setWroteDown(e.target.checked)}
            />
            <span>{m.wroteDown}</span>
          </label>
        </>
      ) : (
        <>
          <label className="np-field">
            <span className="np-label">{m.password}</span>
            <input
              className="np-input"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <label className="np-field">
            <span className="np-label">{m.repeat}</span>
            <input
              className="np-input"
              type="password"
              autoComplete="new-password"
              value={repeat}
              onChange={(e) => setRepeat(e.target.value)}
            />
          </label>
          {error && <p className="np-message np-error">{error}</p>}
          <button
            type="button"
            className="np-button np-filled"
            disabled={password.length < MIN_PASSWORD}
            onClick={() => show(true)}
          >
            {m.show}
          </button>
          <button type="button" className="np-button np-text" onClick={() => show(false)}>
            {m.showPlain}
          </button>
          <p className="np-hint">{m.plainWarning}</p>
        </>
      )}

      <h3 className="np-label">{m.fileTitle}</h3>
      <p className="np-hint">{m.fileExplain}</p>
      <button type="button" className="np-button np-tonal" onClick={() => void download()}>
        {m.download}
      </button>
      {canShare && (
        <button type="button" className="np-button np-text" onClick={() => void share()}>
          {m.share}
        </button>
      )}
      <p className="np-hint">{m.sameAccount}</p>
      {fileSaved && <p className="np-message np-success">{m.saved}</p>}

      <div className="welcome-actions">
        <button
          type="button"
          className="np-button np-filled"
          disabled={!done}
          onClick={() => onDone(key?.method ?? 'ncryptsec')}
        >
          {m.done}
        </button>
        <button type="button" className="np-button np-text" onClick={onCancel}>
          {m.later}
        </button>
      </div>
    </section>
  );
}
