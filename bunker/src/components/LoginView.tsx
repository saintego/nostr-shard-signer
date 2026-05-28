interface Props {
    onConnect: () => void;
}

export function LoginView({ onConnect }: Props) {
    return (
        <div id="view-button" className="view active">
            <button className="login-btn" onClick={onConnect}>
                Sign in
            </button>
        </div>
    );
}
