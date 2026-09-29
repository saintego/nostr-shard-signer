interface Props {
    onConnect: () => void;
    // Why Web3Auth sign-in is unavailable, when the button falls back to the Nostr signer.
    notice?: string | null;
}

export function LoginView({ onConnect, notice }: Props) {
    return (
        <div id="view-button" className="view active">
            <button className="login-btn" onClick={onConnect} title={notice || undefined}>
                Sign in
            </button>
        </div>
    );
}
