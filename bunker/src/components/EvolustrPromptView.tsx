import type { ReactNode } from 'react';
import type { EvolustrAnswer, EvolustrPrompt } from '../types';

interface Props {
    prompt: EvolustrPrompt;
    /** The verified host page asking (event.origin), never an app-supplied name. */
    origin: string;
    waiting?: number;
    onAnswer: (answer: EvolustrAnswer) => void;
}

const hostOf = (s: string) => {
    try { return new URL(s).host; } catch (_) { return s; }
};

/** The app id as the user knows it: a host for web origins, the npub for nsites. */
const appLabel = (appId: string) => (appId.startsWith('nsite:') ? `the nsite ${appId.slice(6, 22)}…` : hostOf(appId));

export function EvolustrPromptView({ prompt, origin, waiting = 0, onAnswer }: Props) {
    const site = hostOf(origin);
    let body: ReactNode;

    if (prompt.kind === 'gesture') {
        const unlock = prompt.reason === 'unlock';
        body = (
            <>
                <h3>{unlock ? 'Unlock your app keys' : 'Create a passkey'}</h3>
                <p className="confirm-summary">
                    {unlock
                        ? 'Use your passkey to unlock the keys that protect your app data.'
                        : 'Your device will ask you to create a passkey for this signer.'}
                </p>
                <div className="confirm-actions">
                    <button className="action-btn btn-secondary" onClick={() => onAnswer('deny')}>Cancel</button>
                    <button className="action-btn btn-primary" onClick={() => onAnswer('allow')}>
                        {unlock ? 'Unlock' : 'Continue'}
                    </button>
                </div>
            </>
        );
    } else if (prompt.kind === 'enrollPasskey') {
        body = (
            <>
                <p className="confirm-site">{site} asks:</p>
                <h3>Add a passkey for your app keys?</h3>
                <p className="confirm-summary">
                    A passkey lets this signer unlock the keys that protect your app data on your
                    other devices too.
                </p>
                <div className="confirm-actions">
                    <button className="action-btn btn-secondary" onClick={() => onAnswer('deny')}>Cancel</button>
                    <button className="action-btn btn-primary" onClick={() => onAnswer('allow')}>Continue</button>
                </div>
            </>
        );
    } else {
        const app = appLabel(prompt.appId);
        body = (
            <>
                <p className="confirm-site">{site} asks:</p>
                <h3>Give {app} its own key for your data?</h3>
                <p className="confirm-summary">
                    {app} will encrypt its data with a key only it gets. Other apps can't read that
                    data, even with permission to sign or decrypt.
                </p>
                {prompt.setup === 'choose' && (
                    <>
                        <p className="confirm-summary">How should this signer protect your app keys?</p>
                        <p className="confirm-warning">
                            ⚠️&ensp;With your Google, Apple or X login, whoever runs this site's
                            Web3Auth project could also recover these keys. A passkey keeps them
                            with you alone.
                        </p>
                        <div className="confirm-actions">
                            <button className="action-btn btn-secondary" onClick={() => onAnswer('allow-sk')}>
                                With my login
                            </button>
                            <button className="action-btn btn-primary" onClick={() => onAnswer('allow-passkey')}>
                                With a passkey
                            </button>
                        </div>
                        <button className="action-btn btn-secondary" onClick={() => onAnswer('deny')}>Don't allow</button>
                    </>
                )}
                {prompt.setup === 'passkey' && (
                    <>
                        <p className="confirm-summary">
                            First, create a passkey for this signer: it keeps your app keys safe and
                            unlocks them on your other devices.
                        </p>
                        <div className="confirm-actions">
                            <button className="action-btn btn-secondary" onClick={() => onAnswer('deny')}>Don't allow</button>
                            <button className="action-btn btn-primary" onClick={() => onAnswer('allow-passkey')}>
                                Create passkey
                            </button>
                        </div>
                    </>
                )}
                {prompt.setup === 'none' && (
                    <div className="confirm-actions">
                        <button className="action-btn btn-secondary" onClick={() => onAnswer('deny')}>Don't allow</button>
                        <button className="action-btn btn-primary" onClick={() => onAnswer('allow')}>Allow</button>
                    </div>
                )}
            </>
        );
    }

    return (
        <div id="view-confirm" className="view active">
            {body}
            {waiting > 0 && (
                <p className="confirm-waiting">{waiting} more {waiting === 1 ? 'request' : 'requests'} waiting</p>
            )}
        </div>
    );
}
