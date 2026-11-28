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
/** `idle`: what the signer's tab shows between requests (#90); a popup waits for its one request. */
export function ConfirmPopupView({ keepOpen = false, idle }: { keepOpen?: boolean; idle?: string } = {}) {
    const [served, setServed] = useState<ServedRequest | null | undefined>(undefined);

    // keepOpen: the signer's tab (#90), which serves one request after another.
    useEffect(() => serveConfirmPopup(r => setServed(r && keepOpen ? { ...r, answer: a => { r.answer(a); setServed(undefined); } } : r), keepOpen), [keepOpen]);

    let content;
    if (served === null) {
        content = <p className="confirm-summary">Open this window from the signer to review a request.</p>;
    } else if (served === undefined) {
        content = <p className="confirm-summary">{idle ?? 'Waiting for the signer…'}</p>;
    } else {
        const { request, answer, event } = served;
        if (request.kind === 'rpc') {
            content = (
                <ConfirmView
                    confirmation={{ method: request.method, params: request.params }}
                    origin={request.origin}
                    {...(request.ownPubkey ? { ownPubkey: request.ownPubkey } : {})}
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
