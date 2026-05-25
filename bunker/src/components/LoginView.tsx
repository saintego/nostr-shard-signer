import type { ButtonSize } from '../types';

interface SocialProvider {
    id: string;
    label: string;
    gridLabel: string;
    icon: React.ReactNode;
}

const SOCIAL_PROVIDERS: SocialProvider[] = [
    {
        id: 'google',
        label: 'Sign in with Google',
        gridLabel: 'Google',
        icon: (
            <img
                src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg"
                alt=""
                style={{ width: 20, height: 20, flexShrink: 0 }}
            />
        ),
    },
    {
        id: 'apple',
        label: 'Sign in with Apple',
        gridLabel: 'Apple',
        icon: (
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 814 1000" style={{ width: 18, height: 18, flexShrink: 0 }}>
                <path d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76 0-103.7 40.8-165.9 40.8s-105-43.4-150.3-109.2c-52-77.1-95.1-198.4-95.1-313.6 0-197.8 129.1-302.2 256.1-302.2 66 0 121.2 43.4 162.7 43.4 39.5 0 101.1-46 176.3-46 28.5 0 130.9 2.6 198.3 99.2z" />
            </svg>
        ),
    },
    {
        id: 'twitter',
        label: 'Sign in with Twitter/X',
        gridLabel: 'Twitter/X',
        icon: (
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" style={{ width: 18, height: 18, flexShrink: 0 }}>
                <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.744l7.737-8.835L1.254 2.25H8.08l4.259 5.63L18.244 2.25zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
            </svg>
        ),
    },
    {
        id: 'email_passwordless',
        label: 'Sign in with Email',
        gridLabel: 'Email',
        icon: (
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" style={{ width: 18, height: 18, flexShrink: 0 }}>
                <path fill="#6b7280" d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4-8 5-8-5V6l8 5 8-5v2z" />
            </svg>
        ),
    },
];

interface Props {
    buttonSize: ButtonSize;
    onLogin: (provider: string) => void;
}

export function LoginView({ buttonSize, onLogin }: Props) {
    if (buttonSize === 'large_social_grid') {
        return (
            <div id="view-button" className="view active">
                <div className="social-grid">
                    {SOCIAL_PROVIDERS.map(p => (
                        <button key={p.id} className="social-btn" onClick={() => onLogin(p.id)}>
                            {p.icon} {p.gridLabel}
                        </button>
                    ))}
                </div>
            </div>
        );
    }

    const subset = SOCIAL_PROVIDERS.filter(
        p => p.id === 'google' || p.id === 'email_passwordless',
    );

    return (
        <div id="view-button" className="view active">
            <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 8 }}>
                {subset.map(p => (
                    <button key={p.id} className="login-btn" onClick={() => onLogin(p.id)}>
                        {p.icon} {p.label}
                    </button>
                ))}
            </div>
        </div>
    );
}
