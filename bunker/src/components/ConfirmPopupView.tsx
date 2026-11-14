import { useEffect, useState } from 'react';
import { serveConfirmPopup, type ServedRequest } from '../lib/confirmPopup';
import { ClickGuardContext } from '../lib/clickGuard';
import { encryptKeyBackup } from '../lib/backup';
import { hexToBytes } from '../lib/hex';
import { ConfirmView } from './ConfirmView';
import { EvolustrPromptView } from './EvolustrPromptView';
import { KeyExportView } from './KeyExportView';

/**
 * The top-level window the signer iframe opens for sensitive prompts in shared
 * mode (src/lib/confirmPopup.ts). No page can frame or style it, so its buttons
 * need no click guard.
 */
export function ConfirmPopupView() {
    const [served, setServed] = useState<ServedRequest | null | undefined>(undefined);

    useEffect(() => serveConfirmPopup(setServed), []);

    let content;
    if (served === null) {
        content = <p className="confirm-summary">Open this window from the signer to review a request.</p>;
    } else if (served === undefined) {
        content = <p className="confirm-summary">Waiting for the signer…</p>;
    } else {
        const { request, answer, event } = served;
        if (request.kind === 'rpc') {
            content = (
                <ConfirmView
                    confirmation={{ method: request.method, params: request.params }}
                    origin={request.origin}
                    onApprove={() => answer('approve')}
                    onReject={() => answer('reject')}
                />
            );
        } else if (request.kind === 'evolustr') {
            content = <EvolustrPromptView prompt={request.prompt} origin={request.origin} onAnswer={a => answer(a)} />;
        } else {
            const privateKey = hexToBytes(request.privateKeyHex);
            content = (
                <KeyExportView
                    nsecStr={request.nsecStr}
                    npubStr={request.npubStr}
                    onEncrypt={password => encryptKeyBackup(privateKey, password)}
                    onBackedUp={method => event({ backedUp: method })}
                    onBack={() => answer('done')}
                    shared={request.shared}
                />
            );
        }
    }

    return (
        <ClickGuardContext.Provider value={false}>
            <div className="popup-view">{content}</div>
        </ClickGuardContext.Provider>
    );
}
