interface Props {
    msg: string;
    detail: string;
}

export function ErrorBanner({ msg, detail }: Props) {
    return (
        <div id="error-banner" className="active">
            <span className="err-icon">⚠️</span>
            <p>{msg || 'An unexpected error occurred.'}</p>
            {detail && <small>{detail}</small>}
        </div>
    );
}
