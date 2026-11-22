import { npubEncode } from 'nostr-tools/nip19';
import type { EnvelopeBody } from '../lib/envelope';
import { format } from '../lib/i18n';
import { useMessages } from '../lib/useMessages';
import { providerName } from './AccountQuestionView';
import { linkingMessages } from './LinkingMessages';

interface Props {
  readonly envelope: Extract<EnvelopeBody, { scope: 'restricted' }>;
  /** The site's host. */
  readonly site: string;
  readonly busy: boolean;
  readonly onUse: (pubkey: string) => void;
}

/** A restricted sign-in (#98): only the identities its link opens, nothing else of the account. */
export function RestrictedView({ envelope, site, busy, onUse }: Props) {
  const m = useMessages(linkingMessages);
  const provider = providerName(envelope.primary.provider, m);
  return (
    <section className="welcome-back">
      <h2 className="np-title">{m.restrictedTitle}</h2>
      <p className="np-hint">
        {format(m.restrictedExplain, { provider, masked: envelope.primary.masked })}
      </p>
      <ul className="welcome-list">
        {envelope.identities.map((i) => (
          <li key={i.pubkey} className="np-list-item welcome-item">
            <span className="welcome-identity">
              {i.label && <strong>{i.label}</strong>}
              <span className="np-hint welcome-npub">{npubEncode(i.pubkey)}</span>
            </span>
            <button
              type="button"
              className="np-button np-filled"
              disabled={busy}
              onClick={() => onUse(i.pubkey)}
            >
              {format(m.useOn, { site })}
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
