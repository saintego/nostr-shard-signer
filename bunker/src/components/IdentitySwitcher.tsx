import { npubEncode } from 'nostr-tools/nip19';
import { format } from '../lib/i18n';
import { useMessages } from '../lib/useMessages';
import { identitySwitcherMessages } from './IdentitySwitcherMessages';
import './IdentitySwitcher.css';

export interface SwitchableIdentity {
  readonly pubkey: string;
  readonly label: string | null;
}

interface Props {
  readonly identities: readonly SwitchableIdentity[];
  readonly active: string;
  readonly onSwitch: (pubkey: string) => void;
  /** Opens the global sign-in popup; call from the click. */
  readonly onManage: () => void;
}

const short = (pubkey: string) => {
  const npub = npubEncode(pubkey);
  return `${npub.slice(0, 12)}…${npub.slice(-6)}`;
};

/**
 * The identities paired with this site (#73 D14, #84): switch between them in
 * the widget; adding, creating and unpairing happen in the sign-in window.
 */
export function IdentitySwitcher({ identities, active, onSwitch, onManage }: Props) {
  const m = useMessages(identitySwitcherMessages);
  return (
    <section className="identity-switcher" aria-label={m.title}>
      <h3 className="np-label">{m.title}</h3>
      <ul className="identity-list">
        {identities.map((i, n) => (
          <li key={i.pubkey} className="np-list-item identity-item">
            <span className="identity-name">
              {i.label ?? format(m.unnamed, { n: String(n + 1) })}
              <span className="np-hint identity-npub">{short(i.pubkey)}</span>
            </span>
            {i.pubkey === active ? (
              <span className="np-badge np-primary">{m.active}</span>
            ) : (
              <button
                type="button"
                className="np-button np-outlined np-small"
                onClick={() => onSwitch(i.pubkey)}
              >
                {m.use}
              </button>
            )}
          </li>
        ))}
      </ul>
      {identities.length > 1 && <p className="np-hint">{m.linkable}</p>}
      <button type="button" className="np-button np-tonal" onClick={onManage}>
        {m.manage}
      </button>
      <p className="np-hint">{m.manageHint}</p>
    </section>
  );
}
