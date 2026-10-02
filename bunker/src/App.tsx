import { useState, useEffect, useRef, useCallback } from 'react';
import type { Web3Auth } from '@web3auth/modal';

import type { ViewName, UserProfile, KeyInfo, PendingConfirmation } from './types';
import { validateEmbedding, isLocalhostOrigin } from './lib/origin';
import { fetchRegistrarConfig, checkAuthorization } from './lib/registry';
import type { Authorization } from './lib/registry';
import { fetchAllowlist, isAllowlisted } from './lib/allowlist';
import { initWeb3Auth, extractKey, getProvider } from './lib/web3auth';
import type { KeyMaterial } from './lib/web3auth';
import { fetchProfile, publishProfile, DEFAULT_PUBLISH_RELAYS, DEFAULT_REGISTRY_RELAYS } from './lib/nostr';
import { requiresConfirmation, processRpc, DEFAULT_AUTO_APPROVE_KINDS } from './lib/crypto';
import { npubEncode } from 'nostr-tools/nip19';

import { LoadingOverlay } from './components/LoadingOverlay';
import { ErrorBanner } from './components/ErrorBanner';
import { LoginView } from './components/LoginView';
import { NostrSignerCard } from './components/NostrSignerCard';
import { AvatarView } from './components/AvatarView';
import { ConfirmView } from './components/ConfirmView';
import { ProfileModal } from './components/ProfileModal';
import { KeyExportView } from './components/KeyExportView';

const ROOT_PUBKEY_HEX = '__ROOT_PUBKEY_HEX__';
const DEFAULT_AVATAR = 'https://robohash.org/nostr?set=set4&size=48x48';
// Height of the iframe while the error card shows: enough for the message
// without covering a phone screen like the full modal height would.
const ERROR_CARD_HEIGHT = 260;

interface AppProps {
    parentOrigin: string;
    urlParams: {
        clientId: string;
        registrarUrl: string;
        nostrSigner: 'bunker' | 'extension' | null;
    };
}

export function App({ parentOrigin, urlParams }: AppProps) {
    const { clientId, registrarUrl, nostrSigner } = urlParams;

    // ── View routing ──────────────────────────────────────────────────────────
    const [view, setView] = useState<ViewName>('loading');
    const [error, setError] = useState<{ msg: string; detail: string } | null>(null);
    // The error card is modal-sized; collapsed, it shrinks to a button-sized pill
    // so it no longer covers the host page (most of the screen on a phone).
    const [errorCollapsed, setErrorCollapsed] = useState(false);
    // Set when Web3Auth setup failed but a Nostr signer (window.nostr.js or an
    // extension) is on the page: the Sign in button then opens that signer.
    const [setupError, setSetupError] = useState<string | null>(null);

    // ── Crypto material (private key in ref, display-safe in state) ───────────
    const privateKeyRef = useRef<Uint8Array | null>(null);
    const [keyInfo, setKeyInfo] = useState<KeyInfo | null>(null);
    const web3authRef = useRef<Web3Auth | null>(null);
    // The Sign in button shows on the registry's provisional answer; anything
    // that exposes the key (login, restored session) waits for this final one.
    const authFinalRef = useRef<Promise<boolean>>(Promise.resolve(false));

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
    const [wnjPubkey, setWnjPubkey] = useState<string | null>(null);
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

    // code is also posted to the parent as SIGNER_ERROR, so nostr-bridge.js can
    // log it with a fix hint in the host page's console (where developers look).
    const showError = useCallback((msg: string, detail = '', code = 'SIGNER_ERROR') => {
        setError({ msg, detail });
        setErrorCollapsed(false);
        setView('error');
        postToParent({ type: 'SIGNER_ERROR', code, message: detail ? `${msg}: ${detail}` : msg });
    }, [postToParent]);

    // Non-fatal setup problems, logged in the host page's console by nostr-bridge.js.
    const warnParent = useCallback((code: string, message: string) => {
        console.warn('[signer]', code, message);
        postToParent({ type: 'SIGNER_WARNING', code, message });
    }, [postToParent]);

    // Setup failures (unregistered domain, Web3Auth init) only rule out Web3Auth
    // sign-in. With a Nostr signer on the page, keep the Sign in button and route
    // it there instead of blocking the widget with the error card.
    const failSetup = useCallback((msg: string, detail: string, code: string) => {
        if (!nostrSigner) {
            showError(msg, detail, code);
            return;
        }
        const message = detail ? `${msg}: ${detail}` : msg;
        setSetupError(message);
        postToParent({ type: 'SIGNER_ERROR', code, message });
        // A WNJ_SESSION may already have switched the view to the avatar.
        setView(v => (v === 'loading' || v === 'connecting' ? 'login' : v));
        postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
    }, [nostrSigner, showError, postToParent]);

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
    // NostrBridge.login()/logout() handlers; set during render below, since the
    // callbacks are defined after the message handler.
    const bridgeActionsRef = useRef<{ connect: () => void; logout: () => void }>({
        connect: () => { },
        logout: () => { },
    });
    // NostrBridge.login() arrived while still loading: open once the button shows.
    const pendingLoginRef = useRef(false);

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
                fetchProfile(pk, publishRelays)
                    .then(profile => { if (profile) setUserProfile(profile); })
                    .catch(() => { /* ignore */ });
                return;
            }

            // ── NostrBridge.login() / logout() ───────────────────────────────────
            if (event.data.type === 'OPEN_LOGIN') {
                if (view === 'login') bridgeActionsRef.current.connect();
                else if (view === 'loading') pendingLoginRef.current = true;
                return;
            }
            if (event.data.type === 'LOGOUT') {
                bridgeActionsRef.current.logout();
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
    }, [parentOrigin, keyInfo, autoApproveKinds, postToParent, publishRelays, view]);

    useEffect(() => {
        const listener = (event: MessageEvent) => handleMessageRef.current(event);
        window.addEventListener('message', listener);
        return () => window.removeEventListener('message', listener);
    }, []);

    // ── Send RESIZE messages whenever the view changes ────────────────────────
    useEffect(() => {
        if (view === 'loading') return;
        if (view === 'error') {
            postToParent(errorCollapsed
                ? { type: 'RESIZE', state: 'button' }
                : { type: 'RESIZE', state: 'modal', height: ERROR_CARD_HEIGHT });
            return;
        }
        const resizeState =
            view === 'login' ? 'button' :
                view === 'avatar' ? 'avatar' :
                    'modal';
        postToParent({ type: 'RESIZE', state: resizeState });
    }, [view, errorCollapsed, postToParent]);

    // ── Bootstrap: run once on mount ──────────────────────────────────────────
    useEffect(() => {
        let cancelled = false;

        const bootstrap = async () => {
            // 1. Embedding check
            if (!validateEmbedding(parentOrigin)) {
                showError('Unauthorized context', 'This signer must be embedded in an authorized page.', 'NOT_EMBEDDED');
                return;
            }

            // 2. No clientId: no Web3Auth, the Sign in button opens the Nostr signer.
            if (!clientId) {
                if (!nostrSigner) {
                    showError('No sign-in method', 'No clientId was given and no Nostr signer is available on the page.', 'NO_SIGN_IN_METHOD');
                    return;
                }
                setView('login');
                postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
                return;
            }

            // Web3Auth init shows no UI and exposes nothing until a session is
            // resolved below, so run it while the domain is being checked.
            const w3aInit = initWeb3Auth(clientId).then(
                w3a => ({ w3a, err: null }),
                (err: unknown) => ({ w3a: null, err }),
            );
            console.log('[signer] initWeb3Auth: start');

            // 3. The Web3Auth allowlist decides; the registrar config (registry
            // relays / root pubkey) is needed for the NIP-33 registry.
            const [allowlist, regConfig] = await Promise.all([
                fetchAllowlist(clientId),
                fetchRegistrarConfig(registrarUrl),
            ]);
            if (cancelled) return;
            if (regConfig.relays?.length) setRegistryRelays(regConfig.relays);
            if (regConfig.pubkey) setRootPubkeyHex(regConfig.pubkey);

            const activeRegistryRelays = regConfig.relays?.length ? regConfig.relays : DEFAULT_REGISTRY_RELAYS;
            const activeRootPubkey = regConfig.pubkey ?? ROOT_PUBKEY_HEX;
            const rootPubkeyMissing = activeRootPubkey === ROOT_PUBKEY_HEX || /^__/.test(activeRootPubkey);
            const checkRegistry = () => checkAuthorization(clientId, parentOrigin, activeRootPubkey, activeRegistryRelays);

            // Local testing only: the registrar refuses localhost domains, so a build
            // made with VITE_LOCAL_TEST=true (scripts/local.sh) skips the domain
            // checks for localhost parents. Normal builds never set the flag.
            const localTestBypass = import.meta.env.VITE_LOCAL_TEST === 'true' && isLocalhostOrigin(parentOrigin);
            if (localTestBypass) console.warn('[signer] VITE_LOCAL_TEST: skipping domain checks for', parentOrigin);

            // 4. Domain authorization: the NIP-33 registry or the Web3Auth
            // allowlist must list the origin; a warning names the one that doesn't.
            if (allowlist.status === 'not_found') {
                failSetup('Unknown clientId', 'Web3Auth has no project with this clientId.', 'CLIENT_ID_NOT_FOUND');
                return;
            }
            const allowlisted = allowlist.status === 'ok' && isAllowlisted(allowlist.origins, parentOrigin);
            if (allowlist.status === 'unavailable') {
                console.warn('[signer] Web3Auth allowlist unavailable (%s); using the NIP-33 registry only', allowlist.reason);
            }

            let auth: Authorization;
            if (localTestBypass) {
                auth = { provisional: Promise.resolve(true), final: Promise.resolve(true) };
            } else if (allowlisted) {
                auth = { provisional: Promise.resolve(true), final: Promise.resolve(true) };
                if (rootPubkeyMissing) {
                    warnParent('NOT_IN_REGISTRY', 'The NIP-33 registry could not be checked: no root registry public key.');
                } else {
                    checkRegistry().final.then(ok => {
                        if (!ok && !cancelled) warnParent('NOT_IN_REGISTRY', `"${parentOrigin}" is not registered for this clientId in the NIP-33 registry.`);
                    });
                }
            } else {
                // Fail closed if the root pubkey is missing/placeholder.
                if (rootPubkeyMissing) {
                    showError('Signer misconfiguration', 'Missing root registry public key. Configure registrarUrl or replace __ROOT_PUBKEY_HEX__.', 'MISSING_ROOT_PUBKEY');
                    return;
                }
                auth = checkRegistry();
                if (allowlist.status === 'ok') {
                    auth.final.then(ok => {
                        if (ok && !cancelled) warnParent('NOT_ALLOWLISTED', `"${parentOrigin}" is not in this clientId's Web3Auth allowlist.`);
                    });
                }
            }
            authFinalRef.current = auth.final;
            const denyDomain = () => failSetup('Access denied', `"${parentOrigin}" is not authorized for this clientId.`, 'DOMAIN_NOT_REGISTERED');

            if (!(await auth.provisional)) {
                if (!cancelled) denyDomain();
                return;
            }
            if (cancelled) return;

            // A newer registry event (from a slower relay) removed this domain:
            // drop Web3Auth so the button falls back like an unregistered domain.
            // No logout — the Web3Auth session belongs to the signer, not this
            // page, and logging out would sign the user out on registered sites.
            let revoked = false;
            auth.final.then(ok => {
                if (ok || cancelled) return;
                revoked = true;
                console.warn('[signer] registry: newer event revokes', parentOrigin);
                const w3a = web3authRef.current;
                web3authRef.current = null;
                w3a?.loginModal?.closeModal();
                denyDomain();
            });

            // 5. Initialize Web3Auth
            const { w3a: initialized, err: initErr } = await w3aInit;
            if (cancelled || revoked) return;
            if (!initialized) {
                console.error('[signer] initWeb3Auth: error', initErr);
                failSetup('Web3Auth init failed', (initErr as Error)?.message ?? String(initErr), 'WEB3AUTH_INIT_FAILED');
                return;
            }
            console.log('[signer] initWeb3Auth: done');
            const w3a: Web3Auth = initialized;
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
            const hasProvider = !!getProvider(w3a);

            console.log('[signer] session check: connected=%s provider=%s cachedConnector=%s connectedConnectorName=%s status=%s',
                w3a.connected,
                hasProvider,
                w3aAny.cachedConnector ?? 'null',
                w3aAny.connectedConnectorName ?? 'null',
                w3aAny.status ?? 'unknown');

            const resolveSession = async () => {
                if (!(await auth.final) || cancelled) return;
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
            if (!cancelled) showError('Initialization error', (e as Error).message, 'INIT_ERROR');
        });

        return () => { cancelled = true; };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []); // run once on mount

    // ── Event handlers ────────────────────────────────────────────────────────

    const handleConnect = useCallback(async () => {
        const w3a = web3authRef.current;
        if (!w3a) {
            // Web3Auth setup failed: the Nostr signer is the only way in.
            if (nostrSigner) postToParent({ type: 'OPEN_NOSTR_SIGNER' });
            return;
        }
        // Expand iframe to modal size so Web3Auth's overlay fits
        postToParent({ type: 'RESIZE', state: 'modal' });
        setView('connecting');
        try {
            // Closing the social-login popup rejects connect() with 5114 but
            // Web3Auth keeps its modal open on the login options; keep waiting
            // on it (at modal size) until the user connects or closes the modal.
            for (;;) {
                try {
                    await w3a.connect();
                    break;
                } catch (e) {
                    if ((e as { code?: number }).code !== 5114) throw e;
                }
            }
            // Web3Auth's modal is gone; show the button-sized spinner while the
            // key and profile load ('loading' skips the view-driven RESIZE).
            setView('loading');
            postToParent({ type: 'RESIZE', state: 'button' });
            // Keep the key inside Web3Auth until the registry check is final.
            if (!(await authFinalRef.current) || web3authRef.current !== w3a) return;
            const km = await extractKey(w3a);
            let w3aProfile: { name?: string; picture?: string } | undefined;
            try {
                const info = await w3a.getUserInfo();
                w3aProfile = { name: info.name || undefined, picture: info.profileImage || undefined };
            } catch (_) { }
            await onLoginSuccess(km, w3aProfile);
        } catch (e) {
            // Revoked while the modal was open: the revocation already set the view.
            if (web3authRef.current !== w3a) return;
            // Restore button size (user cancelled or error)
            setView('login');
            const msg = (e as Error).message ?? '';
            if (!/cancel|close|dismiss/i.test(msg)) {
                showError('Login failed', msg, 'LOGIN_FAILED');
            }
        }
    }, [postToParent, onLoginSuccess, showError, nostrSigner]);

    // "Nostr signer or bunker" picked next to Web3Auth's sheet: the bridge opens
    // window.nostr.js on the parent page, and closing Web3Auth rejects connect(),
    // which returns this iframe to the button.
    const handleNostrSigner = useCallback(() => {
        postToParent({ type: 'OPEN_NOSTR_SIGNER' });
        web3authRef.current?.loginModal?.closeModal();
    }, [postToParent]);

    const handleSignerCardHeight = useCallback((height: number) => {
        postToParent({ type: 'RESIZE', state: 'modal', height });
    }, [postToParent]);

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

    bridgeActionsRef.current = { connect: handleConnect, logout: handleLogout };

    useEffect(() => {
        if (view !== 'login' || !pendingLoginRef.current) return;
        pendingLoginRef.current = false;
        handleConnect();
    }, [view, handleConnect]);

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
    if (view === 'error' && error) {
        return (
            <ErrorBanner
                msg={error.msg}
                detail={error.detail}
                collapsed={errorCollapsed}
                onDismiss={() => {
                    // After a failed login, Web3Auth still works: back to the button.
                    if (web3authRef.current) setView('login');
                    else setErrorCollapsed(true);
                }}
                onExpand={() => setErrorCollapsed(false)}
            />
        );
    }
    if (view === 'login') return <LoginView onConnect={handleConnect} notice={setupError} />;
    // Web3Auth's modal is open and draws its own UI over the iframe; with
    // window.nostr.js on the parent page, offer it right above that sheet.
    if (view === 'connecting') {
        return nostrSigner
            ? <NostrSignerCard kind={nostrSigner} onClick={handleNostrSigner} onHeight={handleSignerCardHeight} />
            : null;
    }

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
