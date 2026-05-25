import { useState } from 'react';

interface Props {
    nsecStr: string;
    npubStr: string;
    onBack: () => void;
}

export function KeyExportView({ nsecStr, npubStr, onBack }: Props) {
    const [nsecVisible, setNsecVisible] = useState(false);
    const [nSecCopied, setNSecCopied] = useState(false);
    const [nPubCopied, setNPubCopied] = useState(false);

    const copyText = async (text: string, onCopied: (v: boolean) => void) => {
        try {
            await navigator.clipboard.writeText(text);
            onCopied(true);
            setTimeout(() => onCopied(false), 1500);
        } catch (_) { }
    };

    return (
        <div id="view-export" className="view active">
            <div className="modal-header">
                <button className="back-btn" onClick={onBack} aria-label="Back">
                    ←
                </button>
                <h3>Export Key</h3>
            </div>

            <div className="export-warning">
                ⚠️&ensp;Your secret key grants <strong>full control</strong> of your Nostr identity.
                Never share it with anyone. Store it somewhere safe.
            </div>

            <div className="key-section">
                <label>Public key (npub)</label>
                <div className="key-row">
                    <code className="key-display">{npubStr}</code>
                    <button
                        className="copy-btn"
                        onClick={() => copyText(npubStr, setNPubCopied)}
                        aria-label="Copy npub"
                    >
                        {nPubCopied ? '✓' : '⧉'}
                    </button>
                </div>
            </div>

            <div className="key-section">
                <label>Secret key (nsec)</label>
                <div className="key-row">
                    <code className="key-display">
                        {nsecVisible ? nsecStr : '•'.repeat(Math.min(nsecStr.length, 40))}
                    </code>
                    <button
                        className="copy-btn"
                        onClick={() => setNsecVisible(v => !v)}
                        aria-label={nsecVisible ? 'Hide nsec' : 'Reveal nsec'}
                    >
                        {nsecVisible ? '🙈' : '👁️'}
                    </button>
                    {nsecVisible && (
                        <button
                            className="copy-btn"
                            onClick={() => copyText(nsecStr, setNSecCopied)}
                            aria-label="Copy nsec"
                        >
                            {nSecCopied ? '✓' : '⧉'}
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
}
