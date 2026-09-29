interface Props {
    msg: string;
    detail: string;
    collapsed: boolean;
    onDismiss: () => void;
    onExpand: () => void;
}

export function ErrorBanner({ msg, detail, collapsed, onDismiss, onExpand }: Props) {
    if (collapsed) {
        return (
            <div id="view-button" className="view active">
                <button className="login-btn error-pill" onClick={onExpand} title={detail || msg}>
                    ⚠️ Sign-in unavailable
                </button>
            </div>
        );
    }
    return (
        <div id="error-banner" className="active">
            <button className="err-close" onClick={onDismiss} aria-label="Dismiss">×</button>
            <span className="err-icon">⚠️</span>
            <p>{msg || 'An unexpected error occurred.'}</p>
            {detail && <small>{detail}</small>}
        </div>
    );
}
