import type { ReactNode } from 'react';
import type { EvolustrAnswer, EvolustrPrompt } from '../types';
import { format } from '../lib/i18n';
import { useMessages } from '../lib/useMessages';
import { evolustrPromptMessages } from './EvolustrPromptMessages';
import { GuardedButton } from './GuardedButton';

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
const appLabel = (appId: string, nsiteLabel: string) =>
    appId.startsWith('nsite:') ? format(nsiteLabel, { id: appId.slice(6, 22) }) : hostOf(appId);

export function EvolustrPromptView({ prompt, origin, waiting = 0, onAnswer }: Props) {
    const m = useMessages(evolustrPromptMessages);
    const site = hostOf(origin);
    const siteAsks = <p className="confirm-site">{format(m.siteAsks, { site })}</p>;
    let body: ReactNode;

    if (prompt.kind === 'gesture') {
        const text = {
            unlock: [m.unlockTitle, m.unlockSummary, m.unlockButton],
            enrollPasskey: [m.createTitle, m.createSummary, m.continueButton],
            retry: [m.retryTitle, m.retrySummary, m.retryButton],
            popup: [m.popupTitle, m.popupSummary, m.popupButton],
        }[prompt.reason];
        body = (
            <>
                <h3>{text[0]}</h3>
                <p className="confirm-summary">{text[1]}</p>
                <div className="confirm-actions">
                    <button className="action-btn btn-secondary" onClick={() => onAnswer('deny')}>{m.cancelButton}</button>
                    <GuardedButton className="action-btn btn-primary" onClick={() => onAnswer('allow')}>
                        {text[2]}
                    </GuardedButton>
                </div>
            </>
        );
    } else if (prompt.kind === 'enrollPasskey') {
        body = (
            <>
                {siteAsks}
                <h3>{m.enrollTitle}</h3>
                <p className="confirm-summary">{m.enrollSummary}</p>
                <div className="confirm-actions">
                    <button className="action-btn btn-secondary" onClick={() => onAnswer('deny')}>{m.cancelButton}</button>
                    <GuardedButton className="action-btn btn-primary" onClick={() => onAnswer('allow')}>{m.continueButton}</GuardedButton>
                </div>
            </>
        );
    } else {
        const app = appLabel(prompt.appId, m.nsiteLabel);
        body = (
            <>
                {siteAsks}
                <h3>{format(m.appKeyTitle, { app })}</h3>
                <p className="confirm-summary">{format(m.appKeySummary, { app })}</p>
                {prompt.setup === 'choose' && (
                    <>
                        <p className="confirm-summary">{m.chooseQuestion}</p>
                        <p className="confirm-warning">
                            ⚠️&ensp;{m.chooseWarning}
                        </p>
                        <div className="confirm-actions">
                            <GuardedButton className="action-btn btn-secondary" onClick={() => onAnswer('allow-sk')}>
                                {m.withLogin}
                            </GuardedButton>
                            <GuardedButton className="action-btn btn-primary" onClick={() => onAnswer('allow-passkey')}>
                                {m.withPasskey}
                            </GuardedButton>
                        </div>
                        <button className="action-btn btn-secondary" onClick={() => onAnswer('deny')}>{m.dontAllow}</button>
                    </>
                )}
                {prompt.setup === 'passkey' && (
                    <>
                        <p className="confirm-summary">{m.passkeyFirst}</p>
                        <div className="confirm-actions">
                            <button className="action-btn btn-secondary" onClick={() => onAnswer('deny')}>{m.dontAllow}</button>
                            <GuardedButton className="action-btn btn-primary" onClick={() => onAnswer('allow-passkey')}>
                                {m.createPasskeyButton}
                            </GuardedButton>
                        </div>
                    </>
                )}
                {prompt.setup === 'none' && (
                    <div className="confirm-actions">
                        <button className="action-btn btn-secondary" onClick={() => onAnswer('deny')}>{m.dontAllow}</button>
                        <GuardedButton className="action-btn btn-primary" onClick={() => onAnswer('allow')}>{m.allow}</GuardedButton>
                    </div>
                )}
            </>
        );
    }

    return (
        <div id="view-confirm" className="view active">
            {body}
            {waiting > 0 && (
                <p className="confirm-waiting">{format(waiting === 1 ? m.waitingOne : m.waitingMany, { count: waiting })}</p>
            )}
        </div>
    );
}
