import type { Custody } from '../lib/evolustr';

export interface EvolustrStatus {
    /** The signer's master key is set up (a signer vault exists or M is unlocked). */
    setUp: boolean;
    /** Protected by the user's nsec (an sk wrap). */
    nsecProtected: boolean;
    signerPasskey: boolean;
}

interface Props {
    status: EvolustrStatus | null;
    apps: string[];
    /** OAuth mode: the signer holds the nsec, so the user picks the protection. */
    holdsNsec: boolean;
    custody: Custody | null;
    busy: boolean;
    message: string;
    onForgetApp: (appId: string) => void;
    onAddPasskey: () => void;
}

const label = (appId: string) => {
    if (appId.startsWith('nsite:')) return `nsite ${appId.slice(6, 22)}…`;
    try { return new URL(appId).host; } catch (_) { return appId; }
};

/** Settings section for the Evolustr Signer API (evolustr SPEC §5.5 rule 4). */
export function EvolustrSettings({ status, apps, holdsNsec, custody, busy, message, onForgetApp, onAddPasskey }: Props) {
    let protection: string;
    if (!status) protection = 'Checking…';
    else if (!status.setUp) protection = 'Not set up yet. Apps that support it will ask when they need a key.';
    else if (status.nsecProtected && status.signerPasskey) protection = 'Protected by your login and by a passkey.';
    else if (status.nsecProtected) protection = 'Protected by your login.';
    else protection = 'Protected by a passkey.';

    const usesLogin = holdsNsec && (custody === 'sk' || status?.nsecProtected === true);

    return (
        <section className="settings-section">
            <h4>App data keys</h4>
            <p className="settings-hint">
                Apps that support Evolustr get their own key from this signer, so other apps
                can't read their data.
            </p>
            <p className="evolustr-status">{protection}</p>
            {usesLogin && (
                <p className="settings-hint">
                    Whoever runs this site's Web3Auth project could recover keys protected by your
                    login. Switch to a passkey to keep new data with you alone; it can't take back
                    what they could already read.
                </p>
            )}
            <div className="evolustr-actions">
                <button className="action-btn btn-secondary" disabled={busy} onClick={onAddPasskey}>
                    {usesLogin ? 'Use a passkey instead' : status?.signerPasskey ? 'Add another passkey' : 'Add a passkey'}
                </button>
            </div>
            {message && <p className="settings-hint">{message}</p>}
            {apps.length > 0 && (
                <>
                    <p className="settings-hint">Apps you allowed on this site (forgetting one makes it ask again):</p>
                    {apps.map(app => (
                        <div key={app} className="relay-row evolustr-app-row">
                            <span className="relay-url" title={app}>{label(app)}</span>
                            <button className="relay-remove" onClick={() => onForgetApp(app)} aria-label={`Forget ${app}`}>
                                ✕
                            </button>
                        </div>
                    ))}
                </>
            )}
        </section>
    );
}
