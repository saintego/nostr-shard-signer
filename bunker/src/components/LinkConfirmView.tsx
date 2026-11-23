import { npubEncode } from 'nostr-tools/nip19';
import { useState } from 'react';
import type { Primary } from '../lib/envelope';
import type { ListedIdentity } from '../lib/globalListModel';
import { format } from '../lib/i18n';
import { useMessages } from '../lib/useMessages';
import { providerName } from './AccountQuestionView';
import { linkingMessages } from './LinkingMessages';

/** Why a sign-in can't be linked, for the user (review 8, items 4 and 8). */
export const refusalText = (
  refusal: 'same-login' | 'own-account' | 'linked-elsewhere' | 'unknown' | null,
  lm: (typeof linkingMessages)['en']
) =>
  refusal === null
    ? null
    : {
        'same-login': lm.refusedSame,
        'own-account': lm.refusedOwn,
        'linked-elsewhere': lm.refusedElsewhere,
        unknown: lm.refusedUnknown,
      }[refusal];

interface Props {
  /** Why this sign-in can't be linked (review 8): shown instead of the question. */
  readonly refused?: string | null;
  /** The sign-in being linked, from Web3Auth's user info (review 8, item 7). */
  readonly provider: string;
  readonly masked: string;
  /** Who created the account. */
  readonly primary: Primary | null;
  /** Derived identities that a restricted link may open. */
  readonly identities: readonly ListedIdentity[];
  readonly busy: boolean;
  /** 'full', or the pubkeys a restricted link opens. */
  readonly onConfirm: (scope: 'full' | readonly string[]) => void;
  readonly onCancel: () => void;
}

/**
 * "Link X account @alice to this account?" (#73 D25, review 8): shown before
 * anything is sealed, with what it opens and the warnings, and the choice
 * between all identities and a restricted link (#98).
 */
export function LinkConfirmView({
  refused = null,
  provider,
  masked,
  primary,
  identities,
  busy,
  onConfirm,
  onCancel,
}: Props) {
  const m = useMessages(linkingMessages);
  const name = providerName(provider, m);
  const [scope, setScope] = useState<'full' | 'some'>('full');
  const [chosen, setChosen] = useState<readonly string[]>([]);
  const toggle = (pubkey: string) =>
    setChosen((c) => (c.includes(pubkey) ? c.filter((p) => p !== pubkey) : [...c, pubkey]));
  const ready = scope === 'full' || chosen.length > 0;
  if (refused)
    return (
      <section className="welcome-back">
        <p className="np-message np-error">{refused}</p>
        <button type="button" className="np-button np-filled" onClick={onCancel}>
          {m.cancel}
        </button>
      </section>
    );
  return (
    <section className="welcome-back">
      <h2 className="np-title">{format(m.linkTitle, { provider: name, masked })}</h2>
      <label className="np-checkbox welcome-profile">
        <input
          type="radio"
          name="scope"
          checked={scope === 'full'}
          onChange={() => setScope('full')}
        />
        <span>{m.scopeAll}</span>
      </label>
      <label className="np-checkbox welcome-profile">
        <input
          type="radio"
          name="scope"
          checked={scope === 'some'}
          onChange={() => setScope('some')}
        />
        <span>{m.scopeSome}</span>
      </label>
      {scope === 'some' && (
        <ul className="welcome-list">
          {identities.map((i) => (
            <li key={i.pubkey} className="np-list-item">
              <label className="np-checkbox welcome-profile">
                <input
                  type="checkbox"
                  checked={chosen.includes(i.pubkey)}
                  onChange={() => toggle(i.pubkey)}
                />
                <span>
                  {i.label ?? `#${(i.index ?? 0) + 1}`}
                  <span className="np-hint welcome-npub">{npubEncode(i.pubkey)}</span>
                </span>
              </label>
            </li>
          ))}
        </ul>
      )}
      <p className="np-message np-warning">
        {format(scope === 'full' ? m.linkWarnFull : m.linkWarnRestricted, { provider: name })}
      </p>
      {primary && (
        <p className="np-hint">
          {format(m.linkPrimary, { provider: providerName(primary.provider, m) })}
        </p>
      )}
      <div className="welcome-actions">
        <button
          type="button"
          className="np-button np-filled"
          disabled={busy || !ready}
          onClick={() => onConfirm(scope === 'full' ? 'full' : chosen)}
        >
          {m.link}
        </button>
        <button type="button" className="np-button np-text" disabled={busy} onClick={onCancel}>
          {m.cancel}
        </button>
      </div>
    </section>
  );
}
