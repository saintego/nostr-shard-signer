import type { GlobalAccount } from '../lib/globalAccount';
import { format } from '../lib/i18n';
import type { Choice } from '../lib/popupLogin';
import { useMessages } from '../lib/useMessages';
import { providerName } from './AccountQuestionView';
import { linkingMessages } from './LinkingMessages';

interface Props {
  readonly account: GlobalAccount;
  readonly busy: boolean;
  /** Signs in with another provider (from the click), then asks to link it. */
  readonly onLink: (choice: Choice) => void;
  /** Web3Auth's panel (['panel']) or the signer's provider buttons (#113). */
  readonly choices: readonly Choice[];
  readonly onUnlink: (pointerPubkey: string) => void;
}

const day = (iso: string) => iso.slice(0, 10);

/** "Manage": the sign-ins of this account (#73 D25, #98). The primary can't be unlinked. */
export function LinkedSignIns({ account, busy, onLink, onUnlink, choices }: Props) {
  const m = useMessages(linkingMessages);
  const live = account.links.filter((l) => !l.unlinkedAt);
  const used = new Set([account.primary?.provider, ...live.map((l) => l.provider)]);
  return (
    <section className="welcome-back">
      <h3 className="np-label">{m.signInsTitle}</h3>
      <ul className="welcome-list">
        {account.primary && (
          <li className="np-list-item">
            {format(m.primaryRow, {
              provider: providerName(account.primary.provider, m),
              masked: account.primary.masked,
            })}
          </li>
        )}
        {live.map((l) => (
          <li key={l.pointerPubkey} className="np-list-item welcome-item">
            <span>
              {format(m.linkedRow, {
                provider: providerName(l.provider, m),
                masked: l.masked,
                date: day(l.linkedAt),
              })}
              {l.scope !== 'full' && (
                <span className="np-hint">
                  {' '}
                  · {format(m.restrictedRow, { n: String(l.scope.length) })}
                </span>
              )}
            </span>
            <button
              type="button"
              className="np-button np-outlined np-danger"
              disabled={busy}
              onClick={() => onUnlink(l.pointerPubkey)}
            >
              {m.unlink}
            </button>
          </li>
        ))}
      </ul>
      {live.length > 0 && <p className="np-hint">{m.unlinkHint}</p>}
      {account.primary &&
        choices
          .filter((p) => !used.has(p))
          .map((p) => (
            <button
              key={p}
              type="button"
              className="np-button np-tonal"
              disabled={busy}
              onClick={() => onLink(p)}
            >
              {p === 'panel' ? m.linkAnother : `${m.linkAnother}: ${providerName(p, m)}`}
            </button>
          ))}
    </section>
  );
}
