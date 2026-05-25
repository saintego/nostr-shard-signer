import { useState, useRef, useEffect } from 'react';
import type { UserProfile, KeyInfo } from '../types';

type TabId = 'profile' | 'keys' | 'settings';

interface Props {
    keyInfo: KeyInfo;
    profile: UserProfile;
    publishRelays: string[];
    autoApproveKinds: Set<number>;
    onSaveProfile: (profile: UserProfile) => Promise<void>;
    onExportKey: () => void;
    onLogout: () => void;
    onRelaysChange: (relays: string[]) => void;
    onAutoApproveChange: (kinds: Set<number>) => void;
    onClose: () => void;
}

const ALL_KNOWN_KINDS: { kind: number; label: string }[] = [
    { kind: 1, label: 'Short notes (kind 1)' },
    { kind: 6, label: 'Reposts (kind 6)' },
    { kind: 7, label: 'Reactions (kind 7)' },
    { kind: 42, label: 'Channel messages (kind 42)' },
];

export function ProfileModal({
    keyInfo,
    profile,
    publishRelays,
    autoApproveKinds,
    onSaveProfile,
    onExportKey,
    onLogout,
    onRelaysChange,
    onAutoApproveChange,
    onClose,
}: Props) {
    const [activeTab, setActiveTab] = useState<TabId>('profile');

    // --- Profile tab state ---
    const [name, setName] = useState(profile.name ?? '');
    const [picture, setPicture] = useState(profile.picture ?? '');
    const [about, setAbout] = useState(profile.about ?? '');
    const [lud16, setLud16] = useState(profile.lud16 ?? '');
    const [saving, setSaving] = useState(false);
    const [saveMsg, setSaveMsg] = useState('');
    const saveMsgTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

    // Clear pending timer on unmount to prevent state update on unmounted component
    useEffect(() => {
        return () => {
            if (saveMsgTimer.current !== null) clearTimeout(saveMsgTimer.current);
        };
    }, []);

    const handleSaveProfile = async () => {
        setSaving(true);
        setSaveMsg('');
        if (saveMsgTimer.current !== null) clearTimeout(saveMsgTimer.current);
        try {
            await onSaveProfile({ name, picture, about, lud16 });
            setSaveMsg('Saved ✓');
        } catch (e) {
            setSaveMsg(`Error: ${(e as Error).message}`);
        } finally {
            setSaving(false);
            saveMsgTimer.current = setTimeout(() => setSaveMsg(''), 2500);
        }
    };

    // --- Keys tab state ---
    const [nsecVisible, setNsecVisible] = useState(false);
    const [npubCopied, setNpubCopied] = useState(false);
    const [nsecCopied, setNsecCopied] = useState(false);

    const copyText = async (text: string, onCopied: (v: boolean) => void) => {
        try {
            await navigator.clipboard.writeText(text);
            onCopied(true);
            setTimeout(() => onCopied(false), 1500);
        } catch (_) { }
    };

    // --- Settings tab state ---
    const [relayInput, setRelayInput] = useState('');

    const toggleKind = (kind: number) => {
        const next = new Set(autoApproveKinds);
        next.has(kind) ? next.delete(kind) : next.add(kind);
        onAutoApproveChange(next);
    };

    const addRelay = () => {
        const url = relayInput.trim();
        if (!url || publishRelays.includes(url)) return;
        onRelaysChange([...publishRelays, url]);
        setRelayInput('');
    };

    const removeRelay = (relay: string) => {
        onRelaysChange(publishRelays.filter(r => r !== relay));
    };

    return (
        <div id="view-profile" className="view active modal-view">
            <div className="modal-header">
                <h3>My Nostr Identity</h3>
                <button className="close-btn" onClick={onClose} aria-label="Close">
                    ✕
                </button>
            </div>

            <div className="tab-bar">
                {(['profile', 'keys', 'settings'] as TabId[]).map(tab => (
                    <button
                        key={tab}
                        className={`tab-btn${activeTab === tab ? ' active' : ''}`}
                        onClick={() => setActiveTab(tab)}
                    >
                        {tab.charAt(0).toUpperCase() + tab.slice(1)}
                    </button>
                ))}
            </div>

            {/* ── Profile tab ── */}
            {activeTab === 'profile' && (
                <div className="tab-content">
                    <div className="field-row">
                        <label htmlFor="pm-name">Display name</label>
                        <input
                            id="pm-name"
                            type="text"
                            value={name}
                            onChange={e => setName(e.target.value)}
                            placeholder="Satoshi"
                        />
                    </div>
                    <div className="field-row">
                        <label htmlFor="pm-picture">Avatar URL</label>
                        <input
                            id="pm-picture"
                            type="url"
                            value={picture}
                            onChange={e => setPicture(e.target.value)}
                            placeholder="https://…"
                        />
                    </div>
                    <div className="field-row">
                        <label htmlFor="pm-about">About</label>
                        <textarea
                            id="pm-about"
                            rows={3}
                            value={about}
                            onChange={e => setAbout(e.target.value)}
                            placeholder="A short bio"
                        />
                    </div>
                    <div className="field-row">
                        <label htmlFor="pm-lud16">Lightning address</label>
                        <input
                            id="pm-lud16"
                            type="email"
                            value={lud16}
                            onChange={e => setLud16(e.target.value)}
                            placeholder="user@wallet.example"
                        />
                    </div>
                    <div className="modal-actions">
                        {saveMsg && <span className="save-msg">{saveMsg}</span>}
                        <button
                            className="action-btn btn-primary"
                            onClick={handleSaveProfile}
                            disabled={saving}
                        >
                            {saving ? 'Saving…' : 'Save to relays'}
                        </button>
                    </div>
                </div>
            )}

            {/* ── Keys tab ── */}
            {activeTab === 'keys' && (
                <div className="tab-content">
                    <div className="key-section">
                        <label>Public key (npub)</label>
                        <div className="key-row">
                            <code className="key-display">{keyInfo.npubStr}</code>
                            <button
                                className="copy-btn"
                                onClick={() => copyText(keyInfo.npubStr, setNpubCopied)}
                                aria-label="Copy npub"
                            >
                                {npubCopied ? '✓' : '⧉'}
                            </button>
                        </div>
                    </div>

                    <div className="key-section">
                        <label>Secret key (nsec)</label>
                        <div className="key-row">
                            <code className="key-display">
                                {nsecVisible ? keyInfo.nsecStr : '•'.repeat(32)}
                            </code>
                            <button
                                className="copy-btn"
                                onClick={() => setNsecVisible(v => !v)}
                                aria-label={nsecVisible ? 'Hide' : 'Reveal'}
                            >
                                {nsecVisible ? '🙈' : '👁️'}
                            </button>
                            {nsecVisible && (
                                <button
                                    className="copy-btn"
                                    onClick={() => copyText(keyInfo.nsecStr, setNsecCopied)}
                                    aria-label="Copy nsec"
                                >
                                    {nsecCopied ? '✓' : '⧉'}
                                </button>
                            )}
                        </div>
                    </div>

                    <div className="modal-actions">
                        <button className="action-btn btn-secondary" onClick={onExportKey}>
                            Export key
                        </button>
                        <button className="action-btn btn-danger" onClick={onLogout}>
                            Log out
                        </button>
                    </div>
                </div>
            )}

            {/* ── Settings tab ── */}
            {activeTab === 'settings' && (
                <div className="tab-content">
                    <section className="settings-section">
                        <h4>Auto-approve event kinds</h4>
                        <p className="settings-hint">
                            Events of these kinds will be signed without a confirmation prompt.
                        </p>
                        {ALL_KNOWN_KINDS.map(({ kind, label }) => (
                            <label key={kind} className="checkbox-row">
                                <input
                                    type="checkbox"
                                    checked={autoApproveKinds.has(kind)}
                                    onChange={() => toggleKind(kind)}
                                />
                                {label}
                            </label>
                        ))}
                    </section>

                    <section className="settings-section">
                        <h4>Publish relays</h4>
                        <p className="settings-hint">Used when saving your profile.</p>
                        {publishRelays.map(r => (
                            <div key={r} className="relay-row">
                                <span className="relay-url">{r}</span>
                                <button
                                    className="relay-remove"
                                    onClick={() => removeRelay(r)}
                                    aria-label={`Remove ${r}`}
                                >
                                    ✕
                                </button>
                            </div>
                        ))}
                        <div className="relay-add-row">
                            <input
                                type="url"
                                value={relayInput}
                                onChange={e => setRelayInput(e.target.value)}
                                onKeyDown={e => e.key === 'Enter' && addRelay()}
                                placeholder="wss://relay.example.com"
                            />
                            <button className="action-btn btn-secondary" onClick={addRelay}>
                                Add
                            </button>
                        </div>
                    </section>
                </div>
            )}
        </div>
    );
}
