import { useState, useEffect, useRef } from 'react';

interface Props {
    nsecStr: string;
    npubStr: string;
    onBack: () => void;
}

export function KeyExportView({ nsecStr, npubStr, onBack }: Props) {
    const [nsecVisible, setNsecVisible] = useState(false);
    const [nsecCopied, setNsecCopied] = useState(false);
    const [npubCopied, setNpubCopied] = useState(false);
    const autoHideTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

    // Clear the auto-hide timer on unmount
    useEffect(() => {
        return () => {
            if (autoHideTimer.current !== null) clearTimeout(autoHideTimer.current);
        };
    }, []);

    const toggleNsec = () => {
        setNsecVisible(v => {
            const next = !v;
            if (autoHideTimer.current !== null) clearTimeout(autoHideTimer.current);
            if (next) {
                // Auto-hide after 10 s
                autoHideTimer.current = setTimeout(() => setNsecVisible(false), 10_000);
            } else {
                autoHideTimer.current = null;
            }
            return next;
        });
    };

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
                        onClick={() => copyText(npubStr, setNpubCopied)}
                        aria-label="Copy npub"
                    >
                        {npubCopied ? '✓' : '⧉'}
                    </button>
                </div>
            </div>

            <div className="key-section">
                <label>Secret key (nsec) — hidden after 10 s</label>
                <div className="key-row">
                    <code className="key-display">
                        {nsecVisible ? nsecStr : '•'.repeat(Math.min(nsecStr.length, 40))}
                    </code>
                    <button
                        className="copy-btn"
                        onClick={toggleNsec}
                        aria-label={nsecVisible ? 'Hide nsec' : 'Reveal nsec'}
                    >
                        {nsecVisible ? '🙈' : '👁️'}
                    </button>
                    {nsecVisible && (
                        <button
                            className="copy-btn"
                            onClick={() => copyText(nsecStr, setNsecCopied)}
                            aria-label="Copy nsec"
                        >
                            {nsecCopied ? '✓' : '⧉'}
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
}
