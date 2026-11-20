import { useState } from 'react';
import { format } from '../lib/i18n';
import { isTrusted, setTrusted } from '../lib/trustCheck';
import { useMessages } from '../lib/useMessages';
import { GuardedButton } from './GuardedButton';
import { trustSettingMessages } from './TrustSettingMessages';

interface Props {
  /** The identity in use on this site. */
  readonly pubkey: string;
  /** The site's host, for the text. */
  readonly site: string;
}

/**
 * Trusted or Ask for this identity on this site (#73 D13, #85). Trusting is a
 * guarded click (#62): a page could otherwise trick the user into it.
 */
export function TrustSetting({ pubkey, site }: Props) {
  const m = useMessages(trustSettingMessages);
  const [trusted, setState] = useState(() => isTrusted(pubkey));
  const choose = (value: boolean) => {
    setTrusted(pubkey, value);
    setState(value);
  };
  return (
    <section className="settings-section">
      <h4>{m.title}</h4>
      <p className="settings-hint">{format(trusted ? m.trusted : m.ask, { site })}</p>
      {trusted ? (
        <button
          type="button"
          className="np-button np-outlined np-small"
          onClick={() => choose(false)}
        >
          {m.untrust}
        </button>
      ) : (
        <>
          <GuardedButton
            type="button"
            className="np-button np-outlined np-small"
            onClick={() => choose(true)}
          >
            {format(m.trust, { site })}
          </GuardedButton>
          <p className="settings-hint">{m.trustHint}</p>
        </>
      )}
    </section>
  );
}
