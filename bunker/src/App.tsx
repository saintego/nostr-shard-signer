import { useState, useEffect, useRef, useCallback } from 'react';
import type { Web3Auth } from '@web3auth/modal';

import type { ViewName, UserProfile, KeyInfo, PendingConfirmation } from './types';
import { validateEmbedding } from './lib/origin';
import { fetchRegistrarConfig, isAuthorized } from './lib/registry';
import { initWeb3Auth, extractKey } from './lib/web3auth';
import type { KeyMaterial } from './lib/web3auth';
import { fetchProfile, publishProfile, DEFAULT_PUBLISH_RELAYS, DEFAULT_REGISTRY_RELAYS } from './lib/nostr';
import { requiresConfirmation, processRpc, DEFAULT_AUTO_APPROVE_KINDS } from './lib/crypto';
import { npubEncode } from 'nostr-tools/nip19';

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
    // ── WNJ profile mode: set when bridge sends WNJ_SESSION ───────────────────────
    const [wnjPubkey, setWnjPubkey] = useState<string | null>(null);    const confCallbackRef = useRef<{
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
    // w3aProfile carries the OAuth provider's name + picture (e.g. from Google),
    // used as fallbacks when the user has no Nostr kind-0 profile yet.
    const onLoginSuccess = useCallback(async (km: KeyMaterial, w3aProfile?: { name?: string; picture?: string }) => {
        privateKeyRef.current = km.privateKeyBytes;
        setKeyInfo({ publicKeyHex: km.publicKeyHex, nsecStr: km.nsecStr, npubStr: km.npubStr });
        postToParent({ type: 'AUTH_SUCCESS', pubkey: km.publicKeyHex });

        const profile = await fetchProfile(km.publicKeyHex, publishRelays);
        // Prefer Nostr kind-0 fields; fall back to the OAuth profile (e.g. Google name/avatar).
        const mergedProfile = profile
            ? { ...profile, name: profile.name || w3aProfile?.name, picture: profile.picture || w3aProfile?.picture }
            : (w3aProfile?.name || w3aProfile?.picture ? w3aProfile : null);
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

            // ── WNJ control messages (no id/method) ────────────────────────────────
            if (event.data.type === 'WNJ_SESSION' && typeof event.data.pubkey === 'string') {
                const pk = event.data.pubkey as string;
                setWnjPubkey(pk);
                setKeyInfo({ publicKeyHex: pk, nsecStr: '', npubStr: npubEncode(pk) });
                postToParent({ type: 'AUTH_STATE', loggedIn: true, pubkey: pk });
                setView('avatar');
                fetchProfile(pk, DEFAULT_PUBLISH_RELAYS)
                    .then(profile => { if (profile) setUserProfile(profile); })
                    .catch(() => { /* ignore */ });
                return;
            }

            if (event.data.type === 'WNJ_DISCONNECT') {
                setWnjPubkey(null);
                setKeyInfo(null);
                setUserProfile({});
                setView('login');
                postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
                return;
            }

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
                console.log('[signer] initWeb3Auth: start');
                w3a = await initWeb3Auth(clientId);
                console.log('[signer] initWeb3Auth: done');
            } catch (e) {
                console.error('[signer] initWeb3Auth: error', e);
                if (!cancelled) showError('Web3Auth init failed', (e as Error).message);
                return;
            }
            if (cancelled) return;
            web3authRef.current = w3a;

            // 6. Resolve existing session.
            // Web3Auth v10 starts connector auto-connect as a non-awaited background
            // task inside init() — w3a.connected is false when init() returns even
            // with a valid cached session.  A fixed-duration await fails on slow
            // networks: the timeout fires before auto-connect finishes, the iframe
            // shows the login button, and the first click on it hits connect()'s
            // "already-connected" short-circuit (which is why "first click works").
            //
            // Fix: stay in 'loading' view and drive transitions from event listeners
            // so the iframe never shows the login button while auto-connect is live.
            // Three terminal events are possible:
            //   "connected"         — auto-connect succeeded  → show avatar
            //   "errored"           — connect() call failed   → show login
            //   "rehydration_error" — sessionId missing/expired → show login
            // A 30 s safety timeout covers the case where none of these fire.

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const w3aAny = w3a as any;
            const hasProvider = !!w3aAny.provider;

            console.log('[signer] session check: connected=%s provider=%s cachedConnector=%s connectedConnectorName=%s status=%s',
                w3a.connected,
                hasProvider,
                w3aAny.cachedConnector ?? 'null',
                w3aAny.connectedConnectorName ?? 'null',
                w3aAny.status ?? 'unknown');

            const resolveSession = async () => {
                console.log('[signer] resolveSession: extracting key');
                try {
                    const km = await extractKey(w3a);
                    console.log('[signer] resolveSession: key extracted, pubkey=%s', km.publicKeyHex);
                    let w3aProfile: { name?: string; picture?: string } | undefined;
                    try {
                        const info = await w3a.getUserInfo();
                        w3aProfile = { name: info.name || undefined, picture: info.profileImage || undefined };
                        console.log('[signer] resolveSession: userInfo ok, name=%s', w3aProfile.name);
                    } catch (e) {
                        console.warn('[signer] resolveSession: getUserInfo failed', e);
                    }
                    if (!cancelled) await onLoginSuccess(km, w3aProfile);
                } catch (e) {
                    console.error('[signer] resolveSession: extractKey failed', e);
                    if (!cancelled) {
                        setView('login');
                        postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
                    }
                }
            };

            // w3a.connected can be true from persisted localStorage state even before
            // the connector has re-initialized (status=not_ready, provider=null).
            // Only take the fast path when there is an actual provider available.
            if (w3a.connected && hasProvider) {
                console.log('[signer] fast path: connected with provider, resolving session');
                await resolveSession();
                return;
            }

            // Determine whether auto-connect will run: either cachedConnector or
            // connectedConnectorName is set from the persisted Web3Auth-state.
            const hasCachedSession = !!(w3aAny.cachedConnector || w3aAny.connectedConnectorName);
            if (!hasCachedSession) {
                console.log('[signer] no cached session → show login');
                setView('login');
                postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
                return;
            }

            // auto-connect is in-flight; stay in 'loading' view and wait for events.
            // cachedConnector is set: auto-connect is running in the background.
            // Register event callbacks and return from bootstrap(); the iframe stays
            // in 'loading' view until one of the events fires.
            const w3aEmitter = w3aAny;

            console.log('[signer] cachedConnector=%s: waiting for auto-connect events',
                (w3a as any).cachedConnector);
            console.log('[signer] w3a event names currently registered:',
                typeof w3aEmitter.eventNames === 'function' ? w3aEmitter.eventNames() : '(not an EventEmitter)');

            const cleanup = (safetyTimer: ReturnType<typeof setTimeout>) => {
                clearTimeout(safetyTimer);
                w3aEmitter.removeListener('connected', onConnected);
                w3aEmitter.removeListener('errored', onFailed);
                w3aEmitter.removeListener('rehydration_error', onFailed);
            };

            // Defined with `let` so they are in scope for cleanup (hoisted).
            // eslint-disable-next-line prefer-const
            let safetyTimer: ReturnType<typeof setTimeout>;

            const onConnected = async () => {
                console.log('[signer] event: connected fired');
                cleanup(safetyTimer);
                if (cancelled) return;
                await resolveSession();
            };

            const onFailed = (eventName: string, err?: unknown) => {
                console.warn('[signer] event: %s fired', eventName, err ?? '');
                cleanup(safetyTimer);
                if (cancelled) return;
                setView('login');
                postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
            };

            safetyTimer = setTimeout(() => {
                console.warn('[signer] safety timeout fired — no auto-connect event received in 30 s');
                w3aEmitter.removeListener('connected', onConnected);
                w3aEmitter.removeListener('errored', onFailed);
                w3aEmitter.removeListener('rehydration_error', onFailed);
                if (cancelled) return;
                setView('login');
                postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
            }, 30000);

            w3aEmitter.once('connected', onConnected);
            w3aEmitter.once('errored', (err: unknown) => onFailed('errored', err));
            w3aEmitter.once('rehydration_error', (err: unknown) => onFailed('rehydration_error', err));
            // bootstrap() returns here; the view stays 'loading' until an event fires.
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
            let w3aProfile: { name?: string; picture?: string } | undefined;
            try {
                const info = await w3a.getUserInfo();
                w3aProfile = { name: info.name || undefined, picture: info.profileImage || undefined };
            } catch (_) { }
            await onLoginSuccess(km, w3aProfile);
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
        if (wnjPubkey) {
            // WNJ profile mode: tell bridge to disconnect WNJ; bridge will send WNJ_DISCONNECT back.
            postToParent({ type: 'WNJ_LOGOUT' });
            return;
        }
        try { await web3authRef.current?.logout(); } catch (_) { }
        // Zero the key material before dropping the reference
        privateKeyRef.current?.fill(0);
        privateKeyRef.current = null;
        setKeyInfo(null);
        setUserProfile({});
        setView('login');
        postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
    }, [postToParent, wnjPubkey]);

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
                isWnjMode={!!wnjPubkey}
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
