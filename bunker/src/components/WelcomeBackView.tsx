import { npubEncode } from 'nostr-tools/nip19';
import { useState } from 'react';
import type { GlobalAccount, NewProfile } from '../lib/globalAccount';
import type { ListedIdentity } from '../lib/globalListModel';
import { format } from '../lib/i18n';
import { useMessages } from '../lib/useMessages';
import { welcomeBackMessages } from './WelcomeBackMessages';
import './WelcomeBack.css';

type Mode = 'choose' | 'create' | 'manage';

interface Props {
  readonly site: string;
  readonly account: GlobalAccount;
  /** The sign-in account's name and picture, offered for new identities (D15). */
  readonly signInProfile: NewProfile | null;
  /** The user picked `pubkey` (now paired); or no identity is left ('none'). */
  readonly onFinish: (pubkey: string | 'none') => void;
  readonly onError: (message: string) => void;
}

const hostOf = (origin: string | null) => {
  try {
    return origin ? new URL(origin).host : '';
  } catch {
    return origin ?? '';
  }
};

const shortNpub = (pubkey: string) => {
  const npub = npubEncode(pubkey);
  return `${npub.slice(0, 12)}…${npub.slice(-6)}`;
};

/**
 * "Welcome back" in the global sign-in popup (#73 D8, D14, D15; #84): the
 * account's identities, where each was created and is used; pair one with the
 * site, create one, or unpair. The popup is top-level, so no click guard.
 */
export function WelcomeBackView({ site, account, signInProfile, onFinish, onError }: Props) {
  const m = useMessages(welcomeBackMessages);
  const [mode, setMode] = useState<Mode>('choose');
  const [busy, setBusy] = useState(false);
  const [, refresh] = useState(0);
  const host = hostOf(site);

  const run = async (step: () => Promise<void>) => {
    setBusy(true);
    try {
      await step();
    } catch (e) {
      onError((e as Error)?.message ?? String(e));
    } finally {
      setBusy(false);
      refresh((n) => n + 1);
    }
  };

  const nameOf = (i: ListedIdentity, n: number) =>
    i.label ?? format(m.unnamed, { n: String((i.index ?? n) + 1) });
  const isPaired = (i: ListedIdentity) => account.paired.some((p) => p.pubkey === i.pubkey);

  if (mode === 'create')
    return (
      <CreateIdentity
        host={host}
        signInProfile={signInProfile}
        busy={busy}
        onBack={() => setMode('choose')}
        onCreate={(label, profile) =>
          run(async () => onFinish((await account.create(label, profile)).pubkey))
        }
      />
    );

  if (mode === 'manage') {
    const paired = account.paired;
    return (
      <section className="welcome-back">
        <h2 className="np-title">{format(m.manageTitle, { site: host })}</h2>
        <ul className="welcome-list">
          {paired.map((i, n) => (
            <li key={i.pubkey} className="np-list-item welcome-item">
              <IdentityText identity={i} name={nameOf(i, n)} />
              <button
                type="button"
                className="np-button np-outlined np-danger"
                disabled={busy}
                onClick={() => void run(() => account.unpair(i.pubkey))}
              >
                {format(m.unpair, { site: host })}
              </button>
            </li>
          ))}
        </ul>
        <p className="np-hint">
          {format(paired.length ? m.unpairHint : m.noneLeft, { site: host })}
        </p>
        <button
          type="button"
          className="np-button np-filled"
          disabled={busy}
          onClick={() => (paired.length ? setMode('choose') : onFinish('none'))}
        >
          {m.done}
        </button>
      </section>
    );
  }

  return (
    <section className="welcome-back">
      <h2 className="np-title">{m.title}</h2>
      <p>{format(m.choose, { site: host })}</p>
      {!account.complete && <p className="np-message np-warning">{m.incomplete}</p>}
      <ul className="welcome-list">
        {account.list.map((i, n) => (
          <li key={i.pubkey} className="np-list-item welcome-item">
            <IdentityText identity={i} name={nameOf(i, n)} />
            <button
              type="button"
              className={`np-button ${isPaired(i) ? 'np-filled' : 'np-outlined'}`}
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  if (!isPaired(i)) await account.pair(i.pubkey);
                  onFinish(i.pubkey);
                })
              }
            >
              {format(isPaired(i) ? m.use : m.pairAndUse, { site: host })}
            </button>
          </li>
        ))}
      </ul>
      <div className="welcome-actions">
        <button
          type="button"
          className="np-button np-tonal"
          disabled={busy}
          onClick={() => setMode('create')}
        >
          {m.create}
        </button>
        {account.paired.length > 0 && (
          <button
            type="button"
            className="np-button np-text"
            disabled={busy}
            onClick={() => setMode('manage')}
          >
            {m.manage}
          </button>
        )}
      </div>
    </section>
  );
}

function IdentityText({ identity, name }: { identity: ListedIdentity; name: string }) {
  const m = useMessages(welcomeBackMessages);
  const sites = identity.sites.map(hostOf).join(', ');
  return (
    <span className="welcome-identity">
      <strong>{name}</strong>
      <span className="np-hint welcome-npub">{shortNpub(identity.pubkey)}</span>
      {identity.createdOn && (
        <span className="np-hint">{format(m.createdOn, { site: hostOf(identity.createdOn) })}</span>
      )}
      <span className="np-hint">{sites ? format(m.pairedWith, { sites }) : m.notPaired}</span>
      {identity.usedElsewhere && <span className="np-hint np-warning">{m.usedElsewhere}</span>}
    </span>
  );
}

interface CreateProps {
  readonly host: string;
  readonly signInProfile: NewProfile | null;
  readonly busy: boolean;
  readonly onBack: () => void;
  readonly onCreate: (label: string | null, profile?: NewProfile) => void;
}

/** "Create a new identity" (D12, D15): the Google name and picture only if asked (default no). */
function CreateIdentity({ signInProfile, busy, onBack, onCreate }: CreateProps) {
  const m = useMessages(welcomeBackMessages);
  const [label, setLabel] = useState('');
  const [useProfile, setUseProfile] = useState(false);
  return (
    <section className="welcome-back">
      <h2 className="np-title">{m.createTitle}</h2>
      <p className="np-hint">{m.createExplain}</p>
      <label className="np-field">
        <span className="np-label">{m.labelField}</span>
        <input
          className="np-input"
          value={label}
          maxLength={100}
          onChange={(e) => setLabel(e.target.value)}
        />
      </label>
      {signInProfile && (signInProfile.name || signInProfile.picture) && (
        <label className="np-checkbox welcome-profile">
          <input
            type="checkbox"
            checked={useProfile}
            onChange={(e) => setUseProfile(e.target.checked)}
          />
          <span>
            {m.useGoogleProfile}
            <span className="np-hint">{m.useGoogleProfileHint}</span>
          </span>
        </label>
      )}
      <div className="welcome-actions">
        <button
          type="button"
          className="np-button np-filled"
          disabled={busy}
          onClick={() =>
            onCreate(label.trim() || null, useProfile && signInProfile ? signInProfile : undefined)
          }
        >
          {m.createConfirm}
        </button>
        <button type="button" className="np-button np-text" disabled={busy} onClick={onBack}>
          {m.back}
        </button>
      </div>
    </section>
  );
}
