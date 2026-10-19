import { useState, useEffect, useRef } from 'react';
import type { BackupMethod } from '../lib/backup';

interface Props {
    nsecStr: string;
    npubStr: string;
    /** Returns the key encrypted with the password (NIP-49 ncryptsec). */
    onEncrypt: (password: string) => string;
    /** The user copied or downloaded a backup. */
    onBackedUp: (method: BackupMethod) => void;
    onBack: () => void;
}

const MIN_PASSWORD = 8;

export function KeyExportView({ nsecStr, npubStr, onEncrypt, onBackedUp, onBack }: Props) {
    const [nsecVisible, setNsecVisible] = useState(false);
    const [nsecCopied, setNsecCopied] = useState(false);
    const [npubCopied, setNpubCopied] = useState(false);
    const autoHideTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

    const [password, setPassword] = useState('');
    const [password2, setPassword2] = useState('');
    const [encrypting, setEncrypting] = useState(false);
    const [ncryptsec, setNcryptsec] = useState('');
    const [ncryptsecCopied, setNcryptsecCopied] = useState(false);
    const [backupError, setBackupError] = useState('');

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

    const copyText = async (text: string, onCopied: (v: boolean) => void): Promise<boolean> => {
        try {
            await navigator.clipboard.writeText(text);
            onCopied(true);
            setTimeout(() => onCopied(false), 1500);
            return true;
        } catch (_) {
            return false;
        }
    };

    const createBackup = () => {
        if (password.length < MIN_PASSWORD) {
            setBackupError(`Use at least ${MIN_PASSWORD} characters.`);
            return;
        }
        if (password !== password2) {
            setBackupError('The passwords don\'t match.');
            return;
        }
        setBackupError('');
        setEncrypting(true);
        // scrypt takes a moment and blocks: let the "Encrypting…" label render first.
        setTimeout(() => {
            try {
                setNcryptsec(onEncrypt(password));
                setPassword('');
                setPassword2('');
            } catch (e) {
                setBackupError((e as Error).message);
            } finally {
                setEncrypting(false);
            }
        }, 20);
    };

    // Needs allow-downloads on the iframe sandbox; Copy works without it.
    const downloadBackup = () => {
        const url = URL.createObjectURL(new Blob([ncryptsec + '\n'], { type: 'text/plain' }));
        const a = document.createElement('a');
        a.href = url;
        a.download = `nostr-key-${npubStr.slice(0, 12)}.ncryptsec.txt`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        onBackedUp('ncryptsec');
    };

    return (
        <div id="view-export" className="view active">
            <div className="modal-header">
                <button className="back-btn" onClick={onBack} aria-label="Back">
                    ←
                </button>
                <h3>Back up your key</h3>
            </div>

            <p className="backup-intro">
                Keep this Nostr account yours, even without this app or the account you signed in with.
            </p>

            <div className="key-section">
                <label>Encrypted backup (recommended)</label>
                {ncryptsec ? (
                    <>
                        <div className="key-row">
                            <code className="key-display">{ncryptsec}</code>
                            <button
                                className="copy-btn"
                                onClick={async () => {
                                    if (await copyText(ncryptsec, setNcryptsecCopied)) onBackedUp('ncryptsec');
                                }}
                                aria-label="Copy encrypted backup"
                            >
                                {ncryptsecCopied ? '✓' : '⧉'}
                            </button>
                        </div>
                        <button className="action-btn btn-secondary" onClick={downloadBackup}>
                            Download backup file
                        </button>
                        <p className="settings-hint">
                            Save it with your passwords. To use it, import it with this password into a
                            Nostr signer that supports encrypted keys (NIP-49).
                        </p>
                    </>
                ) : (
                    <>
                        <input
                            type="password"
                            autoComplete="new-password"
                            placeholder="Password"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                        />
                        <input
                            type="password"
                            autoComplete="new-password"
                            placeholder="Repeat password"
                            value={password2}
                            onChange={e => setPassword2(e.target.value)}
                            onKeyDown={e => { if (e.key === 'Enter') createBackup(); }}
                        />
                        {backupError && <p className="backup-error">{backupError}</p>}
                        <button className="action-btn btn-primary" onClick={createBackup} disabled={encrypting}>
                            {encrypting ? 'Encrypting…' : 'Create encrypted backup'}
                        </button>
                    </>
                )}
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
                            onClick={async () => {
                                if (await copyText(nsecStr, setNsecCopied)) onBackedUp('nsec');
                            }}
                            aria-label="Copy nsec"
                        >
                            {nsecCopied ? '✓' : '⧉'}
                        </button>
                    )}
                </div>
            </div>

            <p className="settings-hint">
                A backup doesn't remove access through this app: whoever runs it can still obtain this key,
                and Nostr keys can't be changed. For an identity nobody else can obtain, create a new key
                in a signer of your own.
            </p>
        </div>
    );
}
