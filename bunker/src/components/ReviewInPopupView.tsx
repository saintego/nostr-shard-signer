import { GuardedButton } from './GuardedButton';

interface Props {
    /** The host page asking. */
    origin: string;
    waiting?: number;
    /** Opens the popup; called synchronously from the click. */
    onReview: () => void;
    onReject: () => void;
    error?: string;
}

/**
 * Shared mode (#62): a sensitive request is shown in a separate window the page
 * can't cover. Here only a neutral button opens it.
 */
export function ReviewInPopupView({ origin, waiting = 0, onReview, onReject, error }: Props) {
    let site = origin;
    try { site = new URL(origin).host; } catch (_) { }
    return (
        <div id="view-confirm" className="view active">
            <p className="confirm-site">{site} sent a request</p>
            <h3>Review this request</h3>
            <p className="confirm-summary">It opens in a separate window, where you can approve or reject it.</p>
            {error && <p className="confirm-warning">⚠️&ensp;{error}</p>}
            <div className="confirm-actions">
                <button className="action-btn btn-secondary" onClick={onReject}>Reject</button>
                <GuardedButton className="action-btn btn-primary" id="review-request" onClick={onReview}>
                    Review this request
                </GuardedButton>
            </div>
            {waiting > 0 && (
                <p className="confirm-waiting">{waiting} more {waiting === 1 ? 'request' : 'requests'} waiting</p>
            )}
        </div>
    );
}
