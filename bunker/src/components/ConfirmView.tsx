import type { PendingConfirmation } from '../types';

const CONFIRM_TITLES: Record<string, string> = {
    nip04_encrypt: 'Allow app to encrypt a direct message?',
    nip04_decrypt: 'Allow app to decrypt a direct message?',
    nip44_encrypt: 'Allow app to encrypt a sealed message?',
    nip44_decrypt: 'Allow app to decrypt a sealed message?',
    sign_event: 'Approve event signature?',
};

interface Props {
    confirmation: PendingConfirmation;
    onApprove: () => void;
    onReject: () => void;
}

export function ConfirmView({ confirmation, onApprove, onReject }: Props) {
    const { method, params } = confirmation;

    let detail: string;
    try {
        if (method === 'sign_event') {
            detail = JSON.stringify(JSON.parse(params[0]), null, 2);
        } else {
            detail = `Method: ${method}\n\nParams:\n${JSON.stringify(params, null, 2)}`;
        }
    } catch (_) {
        detail = `Method: ${method}`;
    }

    return (
        <div id="view-confirm" className="view active">
            <h3>{CONFIRM_TITLES[method] ?? 'Approve request?'}</h3>
            <pre id="confirm-detail">{detail}</pre>
            <div className="confirm-actions">
                <button className="action-btn btn-secondary" onClick={onReject}>
                    Reject
                </button>
                <button className="action-btn btn-primary" onClick={onApprove}>
                    Approve
                </button>
            </div>
        </div>
    );
}
