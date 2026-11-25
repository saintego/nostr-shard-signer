import type { Custody } from '../lib/evolustr';
import { format } from '../lib/i18n';
import { useMessages } from '../lib/useMessages';
import { evolustrSettingsMessages } from './EvolustrSettingsMessages';

export interface EvolustrStatus {
  /** The signer's master key is set up (a signer vault exists or M is unlocked). */
  setUp: boolean;
  /** Protected by the user's nsec (an sk wrap). */
  nsecProtected: boolean;
  signerPasskey: boolean;
  /** The login could open the master key now or did before (evolustr #52). */
  nsecExposed?: boolean;
}

interface Props {
  status: EvolustrStatus | null;
  apps: string[];
  /** OAuth mode: the signer holds the nsec, so the user picks the protection. */
  holdsNsec: boolean;
  custody: Custody | null;
  /** Shared sign-in: the signer's operator runs the Web3Auth project (#66). */
  shared: boolean;
  busy: boolean;
  message: string;
  onForgetApp: (appId: string) => void;
  onAddPasskey: () => void;
}

const label = (appId: string) => {
  if (appId.startsWith('nsite:')) return `nsite ${appId.slice(6, 22)}…`;
  try {
    return new URL(appId).host;
  } catch (_) {
    return appId;
  }
};

/** Settings section for the Evolustr Signer API (evolustr SPEC §5.5 rule 4). */
export function EvolustrSettings({
  status,
  apps,
  holdsNsec,
  custody,
  shared,
  busy,
  message,
  onForgetApp,
  onAddPasskey,
}: Props) {
  const m = useMessages(evolustrSettingsMessages);
  let protection: string;
  if (!status) protection = m.checking;
  else if (!status.setUp) protection = m.notSetUp;
  else if (status.nsecProtected && status.signerPasskey) protection = m.loginAndPasskey;
  else if (status.nsecProtected) protection = m.login;
  else protection = m.passkey;

  const usesLogin = holdsNsec && (custody === 'sk' || status?.nsecProtected === true);
  // #66: a passkey added later doesn't take the login's access away (same master key).
  const exposedOnly = holdsNsec && !usesLogin && status?.nsecExposed === true;
  const who = shared ? m.whoShared : m.whoSite;

  return (
    <section className="settings-section">
      <h4>{m.title}</h4>
      <p className="settings-hint">{m.intro}</p>
      <p className="evolustr-status">{protection}</p>
      {usesLogin && <p className="settings-hint">{format(m.loginRisk, { who })}</p>}
      {exposedOnly && <p className="settings-hint">{format(m.exposed, { who })}</p>}
      <div className="evolustr-actions">
        <button
          type="button"
          className="action-btn btn-secondary"
          disabled={busy}
          onClick={onAddPasskey}
        >
          {status?.signerPasskey ? m.addAnotherPasskey : m.addPasskey}
        </button>
      </div>
      {message && <p className="settings-hint">{message}</p>}
      {apps.length > 0 && (
        <>
          <p className="settings-hint">{m.appsHint}</p>
          {apps.map((app) => (
            <div key={app} className="relay-row evolustr-app-row">
              <span className="relay-url" title={app}>
                {label(app)}
              </span>
              <button
                type="button"
                className="action-btn btn-secondary evolustr-forget"
                onClick={() => onForgetApp(app)}
                aria-label={format(m.forgetLabel, { app })}
              >
                {m.forget}
              </button>
            </div>
          ))}
        </>
      )}
    </section>
  );
}
