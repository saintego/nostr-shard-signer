import type { PendingConfirmation } from '../types';
import { describeRequest } from '../lib/approval';

interface Props {
    confirmation: PendingConfirmation;
    /** The host page asking. */
    origin: string;
    onApprove: () => void;
    onReject: () => void;
}

export function ConfirmView({ confirmation, origin, onApprove, onReject }: Props) {
    const { method, params, waiting = 0 } = confirmation;
    const { title, summary, warning } = describeRequest(method, params);

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

    let site = origin;
    try { site = new URL(origin).host; } catch (_) { }

    return (
        <div id="view-confirm" className="view active">
            <p className="confirm-site">{site} asks:</p>
            <h3>{title}</h3>
            {summary && <p className="confirm-summary">{summary}</p>}
            {warning && <p className="confirm-warning">⚠️&ensp;{warning}</p>}
            <details className="confirm-details">
                <summary>Show details</summary>
                <pre id="confirm-detail">{detail}</pre>
            </details>
            <div className="confirm-actions">
                <button className="action-btn btn-secondary" onClick={onReject}>
                    Reject
                </button>
                <button className="action-btn btn-primary" onClick={onApprove}>
                    Approve
                </button>
            </div>
            {waiting > 0 && (
                <p className="confirm-waiting">{waiting} more {waiting === 1 ? 'request' : 'requests'} waiting</p>
            )}
        </div>
    );
}
