import { useEffect, useState } from 'react';
import { servePasskeyPopup, type PopupRequest } from '../lib/passkeyPopup';

/**
 * The popup the signer iframe opens on its own origin when the browser doesn't
 * allow passkeys inside the iframe (src/lib/passkeyPopup.ts).
 */
export function PasskeyPopupView() {
    const [request, setRequest] = useState<PopupRequest | null | undefined>(undefined);
    const [busy, setBusy] = useState(false);

    useEffect(() => servePasskeyPopup(setRequest), []);

    let content;
    if (request === null) {
        content = <p className="confirm-summary">Open this window from the signer to use your passkey.</p>;
    } else if (request === undefined) {
        content = <p className="confirm-summary">Waiting for the signer…</p>;
    } else {
        const create = request.op === 'create';
        content = (
            <>
                <h3>{create ? 'Create a passkey' : 'Use your passkey'}</h3>
                <p className="confirm-summary">
                    {create
                        ? 'Your device will ask you to create a passkey for this signer. It protects the keys of your app data.'
                        : 'Your device will ask for your passkey to unlock the keys of your app data.'}
                </p>
                <div className="confirm-actions">
                    <button className="action-btn btn-secondary" onClick={() => window.close()}>Cancel</button>
                    <button
                        className="action-btn btn-primary"
                        disabled={busy}
                        onClick={() => { setBusy(true); void request.perform(); }}
                    >
                        Continue
                    </button>
                </div>
            </>
        );
    }

    return <div id="view-confirm" className="view active popup-view">{content}</div>;
}
