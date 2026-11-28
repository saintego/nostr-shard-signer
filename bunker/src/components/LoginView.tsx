import { useMessages } from '../lib/useMessages';
import { loginViewMessages } from './LoginViewMessages';
import './LoginView.css';

interface Props {
  onConnect: () => void;
  /** Sites with their own clientId: Sign up next to Sign in (#73 D5; Sign in never creates an account). */
  onSignUp?: () => void;
  // Why Web3Auth sign-in is unavailable, when the button falls back to the Nostr signer.
  notice?: string | null;
}

export function LoginView({ onConnect, onSignUp, notice }: Props) {
  const m = useMessages(loginViewMessages);
  const signIn = (
    <button type="button" className="login-btn" onClick={onConnect} title={notice || undefined}>
      {m.signIn}
    </button>
  );
  return (
    <div id="view-button" className="view active">
      {onSignUp ? (
        <div className="login-split">
          <button type="button" className="login-btn login-secondary" onClick={onSignUp}>
            {m.signUp}
          </button>
          {signIn}
        </div>
      ) : (
        signIn
      )}
    </div>
  );
}
