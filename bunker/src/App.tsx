import { useState, useEffect, useRef, useCallback } from 'react';
import type { Web3Auth } from '@web3auth/modal';

import type { ViewName, ButtonSize, UserProfile, KeyInfo, PendingConfirmation } from './types';
import { validateEmbedding } from './lib/origin';
import { fetchRegistrarConfig, isAuthorized } from './lib/registry';
import { initWeb3Auth, extractKey } from './lib/web3auth';
import type { KeyMaterial } from './lib/web3auth';
import { fetchProfile, publishProfile, DEFAULT_PUBLISH_RELAYS, DEFAULT_REGISTRY_RELAYS } from './lib/nostr';
import { requiresConfirmation, processRpc, DEFAULT_AUTO_APPROVE_KINDS } from './lib/crypto';

import { LoadingOverlay } from './components/LoadingOverlay';
import { ErrorBanner } from './components/ErrorBanner';
import { LoginView } from './components/LoginView';
import { AvatarView } from './components/AvatarView';
import { ConfirmView } from './components/ConfirmView';
import { ProfileModal } from './components/ProfileModal';
import { KeyExportView } from './components/KeyExportView';

const ROOT_PUBKEY_HEX = '__ROOT_PUBKEY_HEX__';
const DEFAULT_AVATAR = 'https://robohash.org/nostr?set=set4&size=48x48';

interface AppProps {
    parentOrigin: string;
    urlParams: {
        clientId: string;
        registrarUrl: string;
    };
}

export function App({ parentOrigin, urlParams }: AppProps) {
    const { clientId, registrarUrl } = urlParams;

    // ── View routing ──────────────────────────────────────────────────────────
    const [view, setView] = useState<ViewName>('loading');
    const [error, setError] = useState<{ msg: string; detail: string } | null>(null);

    // ── Crypto material (private key in ref, display-safe in state) ───────────
    const privateKeyRef = useRef<Uint8Array | null>(null);
    const [keyInfo, setKeyInfo] = useState<KeyInfo | null>(null);
    const web3authRef = useRef<Web3Auth | null>(null);

    // ── Profile and settings (persisted in localStorage) ──────────────────────
    const [userProfile, setUserProfile] = useState<UserProfile>({});
    const [publishRelays, setPublishRelays] = useState<string[]>(() => {
        try {
            const s = localStorage.getItem('nostr_signer_relays');
            return s ? (JSON.parse(s) as string[]) : DEFAULT_PUBLISH_RELAYS;
        } catch (_) { return DEFAULT_PUBLISH_RELAYS; }
    });
    const [autoApproveKinds, setAutoApproveKinds] = useState<Set<number>>(() => {
        try {
            const s = localStorage.getItem('nostr_signer_auto_kinds');
            return s ? new Set(JSON.parse(s) as number[]) : new Set(DEFAULT_AUTO_APPROVE_KINDS);
        } catch (_) { return new Set(DEFAULT_AUTO_APPROVE_KINDS); }
    });

    // ── Pending signing confirmation ──────────────────────────────────────────
    const [pendingConf, setPendingConf] = useState<PendingConfirmation | null>(null);
    const confCallbackRef = useRef<{
        resolve: (result: string) => void;
        reject: (e: Error) => void;
    } | null>(null);

    // ── Registry config (resolved from registrar) ─────────────────────────────
    const [registryRelays, setRegistryRelays] = useState<string[]>(DEFAULT_REGISTRY_RELAYS);
    const [rootPubkeyHex, setRootPubkeyHex] = useState<string>(ROOT_PUBKEY_HEX);

    // ── Helpers ───────────────────────────────────────────────────────────────

    const postToParent = useCallback(
        (msg: Record<string, unknown>) => {
            if (!parentOrigin) return;
            window.parent.postMessage(msg, parentOrigin);
        },
        [parentOrigin],
    );

    const showError = useCallback((msg: string, detail = '') => {
        setError({ msg, detail });
        setView('error');
    }, []);

    // After login succeeds, populate key state and fetch the Nostr profile.
    // w3aProfileImage is the OAuth provider's profile picture (e.g. Google avatar),
    // used as a fallback when the user has no Nostr kind-0 profile yet.
    const onLoginSuccess = useCallback(async (km: KeyMaterial, w3aProfileImage?: string) => {
        privateKeyRef.current = km.privateKeyBytes;
        setKeyInfo({ publicKeyHex: km.publicKeyHex, nsecStr: km.nsecStr, npubStr: km.npubStr });
        postToParent({ type: 'AUTH_SUCCESS', pubkey: km.publicKeyHex });

        const profile = await fetchProfile(km.publicKeyHex, publishRelays);
        // Prefer the Nostr profile picture; fall back to the OAuth avatar (e.g. Google).
        const mergedProfile = profile
            ? { ...profile, picture: profile.picture || w3aProfileImage }
            : (w3aProfileImage ? { picture: w3aProfileImage } : null);
        if (mergedProfile) setUserProfile(mergedProfile);

        setView('avatar');
    }, [postToParent, publishRelays]);  // use publishRelays, not registryRelays

    // ── postMessage handler (use ref to always capture fresh state) ───────────
    const handleMessageRef = useRef<(event: MessageEvent) => void>(() => { });

    useEffect(() => {
        handleMessageRef.current = async (event: MessageEvent) => {
            if (!event.origin || event.origin === 'null') return;
            if (event.origin !== parentOrigin) return;
            if (event.source !== window.parent) return;

            // Guard against non-object payloads (null, primitives, etc.)
            if (!event.data || typeof event.data !== 'object') return;

            const { id, method, params = [] } = event.data as {
                id: string | number;
                method: string;
                params: string[];
            };

            const pk = privateKeyRef.current;
            const ki = keyInfo;

            if (!pk || !ki) {
                postToParent({ id, error: 'Not authenticated', result: null });
                return;
            }

            // methods that don't need confirmation
            if (!requiresConfirmation(method, params, autoApproveKinds)) {
                try {
                    const result = await processRpc(method, params, pk, ki.publicKeyHex);
                    postToParent({ id, result, error: null });
                } catch (e) {
                    postToParent({ id, result: null, error: (e as Error).message });
                }
                return;
            }

            if (confCallbackRef.current) {
                postToParent({ id, result: null, error: 'Another confirmation is already pending' });
                return;
            }

            // present confirmation dialog and wait for user action;
            // always reply to the parent — even if the user rejects
            try {
                await new Promise<string>((resolve, reject) => {
                    confCallbackRef.current = { resolve, reject };
                    setPendingConf({ method, params });
                    setView('confirm');
                });
                const rpcResult = await processRpc(method, params, pk, ki.publicKeyHex);
                postToParent({ id, result: rpcResult, error: null });
            } catch (e) {
                postToParent({ id, result: null, error: (e as Error).message });
            }
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [parentOrigin, keyInfo, autoApproveKinds, postToParent]);

    useEffect(() => {
        const listener = (event: MessageEvent) => handleMessageRef.current(event);
        window.addEventListener('message', listener);
        return () => window.removeEventListener('message', listener);
    }, []);

    // ── Send RESIZE messages whenever the view changes ────────────────────────
    useEffect(() => {
        if (view === 'loading') return;
        const resizeState =
            view === 'login' ? 'button' :
                view === 'avatar' ? 'avatar' :
                    'modal';
        postToParent({ type: 'RESIZE', state: resizeState });
    }, [view, postToParent]);

    // ── Bootstrap: run once on mount ──────────────────────────────────────────
    useEffect(() => {
        let cancelled = false;

        const bootstrap = async () => {
            // 1. Embedding check
            if (!validateEmbedding(parentOrigin)) {
                showError('Unauthorized context', 'This signer must be embedded in an authorized page.');
                return;
            }

            // 2. clientId required
            if (!clientId) {
                showError('Missing configuration', 'No clientId provided.');
                return;
            }

            // 3. Fetch optional registrar config (extends registry relays / root pubkey)
            const regConfig = await fetchRegistrarConfig(registrarUrl);
            if (cancelled) return;
            if (regConfig.relays?.length) setRegistryRelays(regConfig.relays);
            if (regConfig.pubkey) setRootPubkeyHex(regConfig.pubkey);

            const activeRegistryRelays = regConfig.relays?.length ? regConfig.relays : DEFAULT_REGISTRY_RELAYS;
            const activeRootPubkey = regConfig.pubkey ?? ROOT_PUBKEY_HEX;

            // 4. NIP-33 authorization check (fail closed if root pubkey is missing/placeholder)
            if (activeRootPubkey === ROOT_PUBKEY_HEX || /^__/.test(activeRootPubkey)) {
                showError('Signer misconfiguration', 'Missing root registry public key. Configure registrarUrl or replace __ROOT_PUBKEY_HEX__.');
                return;
            }

            const authorized = await isAuthorized(clientId, parentOrigin, activeRootPubkey, activeRegistryRelays);
            if (cancelled) return;
            if (!authorized) {
                showError('Access denied', `"${parentOrigin}" is not authorized for this clientId.`);
                return;
            }

            // 5. Initialize Web3Auth
            let w3a: Web3Auth;
            try {
                w3a = await initWeb3Auth(clientId);
            } catch (e) {
                if (!cancelled) showError('Web3Auth init failed', (e as Error).message);
                return;
            }
            if (cancelled) return;
            web3authRef.current = w3a;

            // 6. Check for existing session
            if (w3a.connected) {
                try {
                    const km = await extractKey(w3a);
                    let w3aProfileImage: string | undefined;
                    try { w3aProfileImage = (await w3a.getUserInfo()).profileImage || undefined; } catch (_) { }
                    if (!cancelled) await onLoginSuccess(km, w3aProfileImage);
                } catch (_) {
                    if (!cancelled) {
                        setView('login');
                        postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
                    }
                }
            } else {
                if (!cancelled) {
                    setView('login');
                    postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
                }
            }
        };

        bootstrap().catch(e => {
            if (!cancelled) showError('Initialization error', (e as Error).message);
        });

        return () => { cancelled = true; };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []); // run once on mount

    // ── Event handlers ────────────────────────────────────────────────────────

    const handleConnect = useCallback(async () => {
        const w3a = web3authRef.current;
        if (!w3a) return;
        // Expand iframe to modal size so Web3Auth's overlay fits
        postToParent({ type: 'RESIZE', state: 'modal' });
        try {
            await w3a.connect();
            const km = await extractKey(w3a);
            let w3aProfileImage: string | undefined;
            try { w3aProfileImage = (await w3a.getUserInfo()).profileImage || undefined; } catch (_) { }
            await onLoginSuccess(km, w3aProfileImage);
        } catch (e) {
            // Restore button size (user cancelled or error)
            postToParent({ type: 'RESIZE', state: 'button' });
            const msg = (e as Error).message ?? '';
            if (!/cancel|close|dismiss/i.test(msg)) {
                showError('Login failed', msg);
            }
        }
    }, [postToParent, onLoginSuccess, showError]);

    const handleApprove = useCallback(() => {
        const cb = confCallbackRef.current;
        confCallbackRef.current = null;
        setPendingConf(null);
        setView('avatar');
        cb?.resolve('approved');
    }, []);

    const handleReject = useCallback(() => {
        const cb = confCallbackRef.current;
        confCallbackRef.current = null;
        setPendingConf(null);
        setView('avatar');
        cb?.reject(new Error('User rejected'));
    }, []);

    const handleSaveProfile = useCallback(async (profile: UserProfile) => {
        const pk = privateKeyRef.current;
        if (!pk) throw new Error('Not authenticated');
        await publishProfile(profile, pk, publishRelays);
        setUserProfile(profile);
    }, [publishRelays]);

    const handleLogout = useCallback(async () => {
        try { await web3authRef.current?.logout(); } catch (_) { }
        // Zero the key material before dropping the reference
        privateKeyRef.current?.fill(0);
        privateKeyRef.current = null;
        setKeyInfo(null);
        setUserProfile({});
        setView('login');
        postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
    }, [postToParent]);

    const handleRelaysChange = useCallback((relays: string[]) => {
        setPublishRelays(relays);
        localStorage.setItem('nostr_signer_relays', JSON.stringify(relays));
    }, []);

    const handleAutoApproveChange = useCallback((kinds: Set<number>) => {
        setAutoApproveKinds(kinds);
        localStorage.setItem('nostr_signer_auto_kinds', JSON.stringify([...kinds]));
    }, []);

    // ── Render ─────────────────────────────────────────────────────────────────

    if (view === 'loading') return <LoadingOverlay />;
    if (view === 'error' && error) return <ErrorBanner msg={error.msg} detail={error.detail} />;
    if (view === 'login') return <LoginView onConnect={handleConnect} />;

    if (view === 'confirm' && pendingConf) {
        return (
            <ConfirmView
                confirmation={pendingConf}
                onApprove={handleApprove}
                onReject={handleReject}
            />
        );
    }

    if (view === 'export' && keyInfo) {
        return (
            <KeyExportView
                nsecStr={keyInfo.nsecStr}
                npubStr={keyInfo.npubStr}
                onBack={() => setView('profile')}
            />
        );
    }

    if (view === 'profile' && keyInfo) {
        return (
            <ProfileModal
                keyInfo={keyInfo}
                profile={userProfile}
                publishRelays={publishRelays}
                autoApproveKinds={autoApproveKinds}
                onSaveProfile={handleSaveProfile}
                onExportKey={() => setView('export')}
                onLogout={handleLogout}
                onRelaysChange={handleRelaysChange}
                onAutoApproveChange={handleAutoApproveChange}
                onClose={() => setView('avatar')}
            />
        );
    }

    // Default: avatar view
    const avatarUrl = userProfile.picture || DEFAULT_AVATAR;
    return <AvatarView avatarUrl={avatarUrl} onClick={() => setView('profile')} />;
}
