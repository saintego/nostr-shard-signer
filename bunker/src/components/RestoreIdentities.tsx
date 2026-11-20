import { npubEncode } from 'nostr-tools/nip19';
import { useState } from 'react';
import type { ListedIdentity } from '../lib/globalListModel';
import { format } from '../lib/i18n';
import { exportIdentity } from '../lib/restore';
import { useMessages } from '../lib/useMessages';
import { restoreMessages } from './RestoreMessages';

interface Props {
  readonly root: Uint8Array;
  readonly identities: readonly ListedIdentity[];
  /** Called when a key was shown: mark the identity "used elsewhere" (D9). */
  readonly onExported: (identity: ListedIdentity) => void;
}

const host = (o: string) => {
  try {
    return new URL(o).host;
  } catch {
    return o;
  }
};

/** The identities of the restored account, each with its key export (#87). */
export function RestoreIdentities({ root, identities, onExported }: Props) {
  const m = useMessages(restoreMessages);
  return (
    <section className="restore-section">
      <h2 className="np-title">{m.identitiesTitle}</h2>
      <p className="np-message np-warning">{m.evolustrWarning}</p>
      <ul className="welcome-list restore-list">
        {identities.map((i, n) => (
          <li key={i.pubkey} className="np-list-item welcome-item">
            <span className="welcome-identity">
              <strong>{i.label ?? format(m.unnamed, { n: String((i.index ?? n) + 1) })}</strong>
              <span className="np-hint welcome-npub">{npubEncode(i.pubkey)}</span>
              {i.sites.length > 0 && (
                <span className="np-hint">
                  {format(m.usedOn, { sites: i.sites.map(host).join(', ') })}
                </span>
              )}
            </span>
            {i.index !== null && (
              <ExportKey root={root} index={i.index} onShown={() => onExported(i)} />
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

function ExportKey({
  root,
  index,
  onShown,
}: {
  root: Uint8Array;
  index: number;
  onShown: () => void;
}) {
  const m = useMessages(restoreMessages);
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState('');
  const [key, setKey] = useState('');
  const [copied, setCopied] = useState(false);
  const show = async (withPassword: boolean) => {
    setKey(await exportIdentity(root, index, withPassword ? password : undefined));
    onShown();
  };
  if (!open)
    return (
      <button
        type="button"
        className="np-button np-outlined np-small"
        onClick={() => setOpen(true)}
      >
        {m.exportKey}
      </button>
    );
  if (key)
    return (
      <>
        <code className="backup-key">{key}</code>
        <button
          type="button"
          className="np-button np-outlined np-small"
          onClick={() => void navigator.clipboard.writeText(key).then(() => setCopied(true))}
        >
          {copied ? m.copied : m.copy}
        </button>
        <p className="np-hint">{m.exportHint}</p>
      </>
    );
  return (
    <>
      <label className="np-field">
        <span className="np-label">{m.exportPassword}</span>
        <input
          className="np-input"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </label>
      <button
        type="button"
        className="np-button np-filled np-small"
        disabled={password.length < 8}
        onClick={() => void show(true)}
      >
        {m.show}
      </button>
      <button type="button" className="np-button np-text np-small" onClick={() => void show(false)}>
        {m.showPlain}
      </button>
    </>
  );
}
