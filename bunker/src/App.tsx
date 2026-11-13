import { useState, useEffect, useRef, useCallback } from 'react';
import type { Web3Auth } from '@web3auth/modal';

import type { ViewName, UserProfile, KeyInfo, PendingConfirmation, EvolustrPrompt, EvolustrAnswer } from './types';
import { validateEmbedding, isLocalhostOrigin } from './lib/origin';
import { fetchRegistrarConfig, checkAuthorization } from './lib/registry';
import type { Authorization } from './lib/registry';
import { fetchAllowlist, isAllowlisted } from './lib/allowlist';
import { sharedClientIdFor } from './lib/shared';
import { initWeb3Auth, extractKey, getProvider } from './lib/web3auth';
import type { KeyMaterial } from './lib/web3auth';
import { fetchProfile, publishProfile, DEFAULT_PUBLISH_RELAYS, DEFAULT_REGISTRY_RELAYS } from './lib/nostr';
import { processRpc } from './lib/crypto';
import { requiresConfirmation, loadAutoApproveKinds, saveAutoApproveKinds } from './lib/approval';
import { countSignedEvent, shouldAskForBackup, snoozeBackupPrompt, encryptKeyBackup, recordBackup, syncBackupMarker } from './lib/backup';
import type { BackupMethod } from './lib/backup';
import { npubEncode } from 'nostr-tools/nip19';
import { finalizeEvent } from 'nostr-tools/pure';
import {
    createHostSigner, isEvolustrMethod, signerPasskeys, signThroughBridge,
    loadCustody, saveCustody, loadAllowedApps, saveAllowedApps,
} from './lib/evolustr';
import type { Custody, EvolustrSigner, ConfirmRequest, SignerPasskeys } from './lib/evolustr';

import { LoadingOverlay } from './components/LoadingOverlay';
import { ErrorBanner } from './components/ErrorBanner';
import { LoginView } from './components/LoginView';
import { NostrSignerCard } from './components/NostrSignerCard';
import { AvatarView } from './components/AvatarView';
import { ConfirmView } from './components/ConfirmView';
import { ProfileModal } from './components/ProfileModal';
import { KeyExportView } from './components/KeyExportView';
import { EvolustrPromptView } from './components/EvolustrPromptView';
import { EvolustrSettings } from './components/EvolustrSettings';
import type { EvolustrStatus } from './components/EvolustrSettings';

const ROOT_PUBKEY_HEX = '__ROOT_PUBKEY_HEX__';
const DEFAULT_AVATAR = 'https://robohash.org/nostr?set=set4&size=48x48';
// Height of the iframe while the error card shows: enough for the message
// without covering a phone screen like the full modal height would.
const ERROR_CARD_HEIGHT = 260;
// postMessage protocol versions this signer speaks with nostr-bridge.js (see
// PROTOCOL_VERSION there). Keep old versions here while hosted bridges that
// send them may still be cached or pinned.
const SUPPORTED_PROTOCOLS = [1];
// Confirmations waiting for the user beyond this many are refused, so a buggy
// or hostile page can't bury the user in prompts.
const MAX_QUEUED_CONFIRMATIONS = 20;

interface AppProps {
    parentOrigin: string;
    urlParams: {
        clientId: string;
        registrarUrl: string;
        nostrSigner: 'bunker' | 'extension' | null;
        protocol: number;
        poweredBy: boolean;
        nostrOnly: boolean;
    };
}

export function App({ parentOrigin, urlParams }: AppProps) {
    const { registrarUrl, nostrSigner, protocol, poweredBy, nostrOnly } = urlParams;
    // Shared mode: no clientId from the page, so the signer's own project is
    // used (src/lib/shared.ts). Nostr-only pages get no Web3Auth at all.
    const sharedClientId = sharedClientIdFor(urlParams.clientId, nostrOnly);
    const shared = !!sharedClientId;
    const clientId = shared ? sharedClientId : nostrOnly ? '' : urlParams.clientId;

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
    // Per host site: the user may trust one site more than another.
    const [autoApproveKinds, setAutoApproveKinds] = useState<Set<number>>(() => loadAutoApproveKinds(parentOrigin));

    // OAuth users who haven't backed up their key yet are asked to (#37).
    const [backupAsk, setBackupAsk] = useState(false);

    // ── Pending signing confirmations ─────────────────────────────────────────
    // Requests that need the user's OK wait in a queue and are shown one at a
    // time; the head of the queue is the one on screen.
    const [pendingConf, setPendingConf] = useState<PendingConfirmation | null>(null);
    const confQueueRef = useRef<(PendingConfirmation & {
        resolve: (answer?: EvolustrAnswer) => void;
        reject: (e: Error) => void;
    })[]>([]);
    // Where to go back to once the queue is empty (the settings, when a passkey
    // step started there).
    const afterConfirmViewRef = useRef<ViewName>('avatar');

    // ── Evolustr Signer API (src/lib/evolustr.ts) ─────────────────────────────
    const evolustrRef = useRef<EvolustrSigner | null>(null);
    // Requests that arrived right after sign-in, before the signer was created.
    const evolustrWaitersRef = useRef<((s: EvolustrSigner | null) => void)[]>([]);
    const passkeysRef = useRef<SignerPasskeys | null>(null);
    const custodyRef = useRef<Custody | null>(null);
    // Set by a step that already has the user's OK for a passkey enrollment.
    const enrollConsentRef = useRef(false);
    const [evolustrApps, setEvolustrApps] = useState<string[]>([]);
    const [evolustrStatus, setEvolustrStatus] = useState<EvolustrStatus | null>(null);
    const [evolustrBusy, setEvolustrBusy] = useState(false);
    const [evolustrMsg, setEvolustrMsg] = useState('');
    // ── WNJ profile mode: set when bridge sends WNJ_SESSION ───────────────────────
    const [wnjPubkey, setWnjPubkey] = useState<string | null>(null);

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
        setBackupAsk(shouldAskForBackup(km.publicKeyHex));
        // A backup made on another site or device counts here too.
        syncBackupMarker(km.privateKeyBytes, km.publicKeyHex, publishRelays)
            .then(found => { if (found) setBackupAsk(false); });

        const profile = await fetchProfile(km.publicKeyHex, publishRelays);
        // Prefer Nostr kind-0 fields; fall back to the OAuth profile (e.g. Google name/avatar).
        const mergedProfile = profile
            ? { ...profile, name: profile.name || w3aProfile?.name, picture: profile.picture || w3aProfile?.picture }
            : (w3aProfile?.name || w3aProfile?.picture ? w3aProfile : null);
        if (mergedProfile) setUserProfile(mergedProfile);

        setView('avatar');
    }, [postToParent, publishRelays]);  // use publishRelays, not registryRelays

    const showNextConfirmation = useCallback(() => {
        const queue = confQueueRef.current;
        if (queue.length === 0) {
            setPendingConf(null);
            setView(v => (v === 'confirm' ? afterConfirmViewRef.current : v));
            return;
        }
        setPendingConf({ method: queue[0].method, params: queue[0].params, evolustr: queue[0].evolustr, waiting: queue.length - 1 });
        setView('confirm');
    }, []);

    // The session ended: answer every waiting request instead of leaving it hanging.
    const rejectAllConfirmations = useCallback((reason: string) => {
        const queue = confQueueRef.current.splice(0);
        for (const item of queue) item.reject(new Error(reason));
        setPendingConf(null);
    }, []);

    const noteSignedEvent = (pubkeyHex: string) => {
        countSignedEvent(pubkeyHex);
        setBackupAsk(shouldAskForBackup(pubkeyHex));
    };

    // ── Evolustr Signer API ───────────────────────────────────────────────────

    // Shows an Evolustr prompt in the confirmation queue and waits for the answer.
    const askEvolustr = useCallback((prompt: EvolustrPrompt): Promise<EvolustrAnswer> => {
        if (confQueueRef.current.length >= MAX_QUEUED_CONFIRMATIONS)
            return Promise.reject(new Error('Too many confirmations are waiting for the user'));
        return new Promise<EvolustrAnswer>((resolve, reject) => {
            confQueueRef.current.push({
                method: 'evolustr', params: [], evolustr: prompt,
                resolve: answer => resolve(answer ?? 'allow'), reject,
            });
            if (confQueueRef.current.length === 1) showNextConfirmation();
            else setPendingConf(p => (p ? { ...p, waiting: confQueueRef.current.length - 1 } : p));
        });
    }, [showNextConfirmation]);

    // Forget the unlocked master key on this device (logout).
    const lockEvolustr = () => {
        const evolustr = evolustrRef.current;
        evolustrRef.current = null;
        setEvolustrStatus(null);
        void evolustr?.lock();
    };

    // The bridge forwards Evolustr calls as soon as this iframe reports the
    // session, which can be before the effect below has created the signer.
    const waitForEvolustr = () => new Promise<EvolustrSigner | null>(resolve => {
        const timer = setTimeout(() => {
            evolustrWaitersRef.current = evolustrWaitersRef.current.filter(w => w !== waiter);
            resolve(null);
        }, 3000);
        const waiter = (s: EvolustrSigner | null) => { clearTimeout(timer); resolve(s); };
        evolustrWaitersRef.current.push(waiter);
    });

    // The signer itself, as the caller for status checks from the settings.
    const selfCaller = { identity: 'verified' as const, origin: location.origin };

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

            // Answers to EVOLUSTR_SIGN, handled by signThroughBridge.
            if (event.data.type === 'EVOLUSTR_SIGN_RESULT') return;

            if (event.data.type === 'WNJ_DISCONNECT') {
                rejectAllConfirmations('Logged out');
                lockEvolustr();
                setWnjPubkey(null);
                setBackupAsk(false);
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

            // Evolustr Signer API: works with OAuth and with an extension or
            // bunker. The caller is event.origin, never anything in params.
            if (isEvolustrMethod(method)) {
                const evolustr = evolustrRef.current ?? await waitForEvolustr();
                if (!evolustr) {
                    postToParent({ id, error: 'Not authenticated', result: null });
                    return;
                }
                try {
                    const r = await evolustr.handle(method, Array.isArray(params) ? params : [], { identity: 'verified', origin: event.origin });
                    postToParent(r.ok ? { id, result: r.value ?? null, error: null } : { id, result: null, error: r.error.message });
                } catch (e) {
                    postToParent({ id, result: null, error: (e as Error).message || 'Evolustr request failed' });
                }
                return;
            }

            if (!pk || !ki) {
                postToParent({ id, error: 'Not authenticated', result: null });
                return;
            }

            // methods that don't need confirmation
            if (!requiresConfirmation(method, params, autoApproveKinds)) {
                try {
                    const result = await processRpc(method, params, pk, ki.publicKeyHex);
                    postToParent({ id, result, error: null });
                    if (method === 'sign_event') noteSignedEvent(ki.publicKeyHex);
                } catch (e) {
                    postToParent({ id, result: null, error: (e as Error).message });
                }
                return;
            }

            if (confQueueRef.current.length >= MAX_QUEUED_CONFIRMATIONS) {
                postToParent({ id, result: null, error: 'Too many confirmations are waiting for the user' });
                return;
            }

            // Queue the confirmation and wait for the user's answer; always reply
            // to the parent, even if the user rejects. The bridge stops its RPC
            // timeout on CONFIRM_PENDING: the user may take a while to decide.
            postToParent({ type: 'CONFIRM_PENDING', requestId: id });
            try {
                await new Promise<void>((resolve, reject) => {
                    confQueueRef.current.push({ method, params, resolve: () => resolve(), reject });
                    if (confQueueRef.current.length === 1) showNextConfirmation();
                    else setPendingConf(p => (p ? { ...p, waiting: confQueueRef.current.length - 1 } : p));
                });
                const rpcResult = await processRpc(method, params, pk, ki.publicKeyHex);
                postToParent({ id, result: rpcResult, error: null });
                if (method === 'sign_event') noteSignedEvent(ki.publicKeyHex);
            } catch (e) {
                postToParent({ id, result: null, error: (e as Error).message });
            }
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [parentOrigin, keyInfo, autoApproveKinds, postToParent, publishRelays, view, showNextConfirmation, rejectAllConfirmations]);

    useEffect(() => {
        const listener = (event: MessageEvent) => handleMessageRef.current(event);
        window.addEventListener('message', listener);
        return () => window.removeEventListener('message', listener);
    }, []);

    // ── Evolustr signer: one per signed-in user ──────────────────────────────
    const evolustrPubkey = keyInfo?.publicKeyHex ?? null;
    const holdsNsec = !!evolustrPubkey && !wnjPubkey;
    const publishRelaysKey = publishRelays.join(' ');
    useEffect(() => {
        if (!evolustrPubkey) return;
        const pubkey = evolustrPubkey;
        const oauth = holdsNsec;
        custodyRef.current = oauth ? loadCustody(pubkey) : 'passkey';
        setEvolustrApps(loadAllowedApps(pubkey));
        const passkeys = signerPasskeys('Nostr Shard Signer');
        passkeysRef.current = passkeys;

        let evolustr: EvolustrSigner;
        const setCustody = (c: Custody) => {
            custodyRef.current = c;
            if (oauth) saveCustody(pubkey, c);
        };
        const enroll = async () => {
            enrollConsentRef.current = true;
            try {
                const r = await evolustr.enrollPasskey();
                if (!r.ok) throw new Error(r.error.message);
            } finally {
                enrollConsentRef.current = false;
            }
        };

        const confirm = async (req: ConfirmRequest): Promise<boolean> => {
            if (req.kind === 'enrollPasskey') {
                if (enrollConsentRef.current) return true;
                return (await askEvolustr({ kind: 'enrollPasskey' })) === 'allow';
            }
            // What does allowing this app also need? Read the signer vault
            // first (no prompt, nothing published).
            const caps = await evolustr.capabilities(selfCaller);
            if (caps.ok && oauth && custodyRef.current === null) {
                // Chosen on another site or device: the vault on the relays says how.
                if (caps.value.nsecProtected) setCustody('sk');
                else if (caps.value.signerPasskey) setCustody('passkey');
            }
            const ready = caps.ok && (caps.value.ready || caps.value.signerPasskey);
            const needsSetup = !ready && !(oauth && custodyRef.current === 'sk');
            const setup = !needsSetup ? 'none' : oauth && custodyRef.current === null ? 'choose' : 'passkey';
            const apps = loadAllowedApps(pubkey);
            if (setup === 'none' && apps.includes(req.appId)) return true;

            const answer = await askEvolustr({ kind: 'appKey', appId: req.appId, setup });
            if (answer === 'deny') return false;
            if (answer === 'allow-sk') setCustody('sk');
            if (answer === 'allow-passkey') {
                const before = custodyRef.current;
                setCustody('passkey');
                try {
                    await enroll();
                } catch (e) {
                    if (before !== 'passkey' && oauth) {
                        custodyRef.current = before;
                        if (before) saveCustody(pubkey, before);
                    }
                    throw e;
                }
            }
            const next = loadAllowedApps(pubkey);
            if (!next.includes(req.appId)) {
                next.push(req.appId);
                saveAllowedApps(pubkey, next);
                setEvolustrApps(next);
            }
            return true;
        };

        evolustr = createHostSigner({
            pubkey,
            relays: publishRelaysKey.split(' ').filter(Boolean),
            getSecretKey: oauth ? () => privateKeyRef.current : null,
            sign: oauth
                ? async event => {
                    const sk = privateKeyRef.current;
                    if (!sk) throw new Error('Not authenticated');
                    return finalizeEvent({ ...event, tags: event.tags.map(t => [...t]) }, sk);
                }
                : signThroughBridge(postToParent, pubkey),
            custody: () => custodyRef.current,
            passkeys: passkeys.passkeys,
            confirm,
            requestGesture: async reason => {
                if ((await askEvolustr({ kind: 'gesture', reason })) === 'deny') throw new Error('Cancelled');
            },
        });
        evolustrRef.current = evolustr;
        for (const w of evolustrWaitersRef.current.splice(0)) w(evolustr);
        return () => {
            if (evolustrRef.current === evolustr) evolustrRef.current = null;
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [evolustrPubkey, holdsNsec, publishRelaysKey, askEvolustr, postToParent]);

    // Status for the settings: read when they open.
    useEffect(() => {
        if (view !== 'profile') return;
        const evolustr = evolustrRef.current;
        if (!evolustr) return;
        let stale = false;
        evolustr.capabilities(selfCaller).then(r => {
            if (stale || !r.ok) return;
            const c = r.value;
            setEvolustrStatus({ setUp: c.ready || c.signerPasskey || c.nsecProtected, nsecProtected: c.nsecProtected, signerPasskey: c.signerPasskey });
        });
        return () => { stale = true; };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [view, evolustrPubkey]);

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

            // 2. Protocol handshake: refuse a bridge this signer can't talk to
            // instead of misreading its messages.
            if (!SUPPORTED_PROTOCOLS.includes(protocol)) {
                showError('Version mismatch', `nostr-bridge.js speaks protocol ${protocol}; this signer supports ${SUPPORTED_PROTOCOLS.join(', ')}.`, 'PROTOCOL_UNSUPPORTED');
                return;
            }
            // oauth tells the bridge which Google/Apple/X sign-in the page gets:
            // its own clientId, the shared project, or none.
            postToParent({ type: 'SIGNER_HELLO', protocol, oauth: !clientId ? 'none' : shared ? 'shared' : 'own' });

            // 3. No clientId: no Web3Auth, the Sign in button opens the Nostr signer.
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

            // 4–5. Domain authorization. Shared mode is open to every site, so
            // there is nothing to check: the shared project's allowlist lists
            // only the signer's origin, and a registry entry for its clientId
            // (if anyone claimed one) says nothing about who may use it.
            let auth: Authorization;
            if (shared) {
                auth = { provisional: Promise.resolve(true), final: Promise.resolve(true) };
            } else {
                // The Web3Auth allowlist decides; the registrar config (registry
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

                // The NIP-33 registry or the Web3Auth allowlist must list the
                // origin; a warning names the one that doesn't.
                if (allowlist.status === 'not_found') {
                    failSetup('Unknown clientId', 'Web3Auth has no project with this clientId.', 'CLIENT_ID_NOT_FOUND');
                    return;
                }
                const allowlisted = allowlist.status === 'ok' && isAllowlisted(allowlist.origins, parentOrigin);
                if (allowlist.status === 'unavailable') {
                    console.warn('[signer] Web3Auth allowlist unavailable (%s); using the NIP-33 registry only', allowlist.reason);
                }

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

            // 6. Initialize Web3Auth
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

            // 7. Resolve existing session.
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
        confQueueRef.current.shift()?.resolve();
        showNextConfirmation();
    }, [showNextConfirmation]);

    const handleReject = useCallback(() => {
        confQueueRef.current.shift()?.reject(new Error('User rejected'));
        showNextConfirmation();
    }, [showNextConfirmation]);

    const handleEvolustrAnswer = useCallback((answer: EvolustrAnswer) => {
        const head = confQueueRef.current[0];
        // A passkey popup must open in this click, or the browser blocks it.
        if (head?.evolustr?.kind === 'gesture' && answer === 'allow') passkeysRef.current?.onGesture();
        confQueueRef.current.shift()?.resolve(answer);
        showNextConfirmation();
    }, [showNextConfirmation]);

    const handleForgetApp = useCallback((appId: string) => {
        if (!keyInfo) return;
        const next = loadAllowedApps(keyInfo.publicKeyHex).filter(a => a !== appId);
        saveAllowedApps(keyInfo.publicKeyHex, next);
        setEvolustrApps(next);
    }, [keyInfo]);

    // "Add a passkey" / "Use a passkey instead" in the settings.
    const handleEvolustrPasskey = useCallback(async () => {
        const evolustr = evolustrRef.current;
        if (!evolustr || !keyInfo) return;
        const pubkey = keyInfo.publicKeyHex;
        const oauth = !wnjPubkey;
        const before = custodyRef.current;
        setEvolustrBusy(true);
        setEvolustrMsg('');
        afterConfirmViewRef.current = 'profile';
        // OAuth: from now on M is protected by passkeys only; the sk wrap is
        // dropped when the passkey is added.
        custodyRef.current = 'passkey';
        enrollConsentRef.current = true;
        try {
            const r = await evolustr.enrollPasskey();
            if (!r.ok) throw new Error(r.error.message);
            if (oauth) saveCustody(pubkey, 'passkey');
            setEvolustrMsg('Passkey added ✓');
            const caps = await evolustr.capabilities(selfCaller);
            if (caps.ok) setEvolustrStatus({
                setUp: true, nsecProtected: caps.value.nsecProtected, signerPasskey: caps.value.signerPasskey,
            });
        } catch (e) {
            custodyRef.current = before;
            setEvolustrMsg(`Error: ${(e as Error).message}`);
        } finally {
            enrollConsentRef.current = false;
            afterConfirmViewRef.current = 'avatar';
            setEvolustrBusy(false);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [keyInfo, wnjPubkey]);

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
        rejectAllConfirmations('Logged out');
        lockEvolustr();
        try { await web3authRef.current?.logout(); } catch (_) { }
        // Zero the key material before dropping the reference
        privateKeyRef.current?.fill(0);
        privateKeyRef.current = null;
        setKeyInfo(null);
        setBackupAsk(false);
        setUserProfile({});
        setView('login');
        postToParent({ type: 'AUTH_STATE', loggedIn: false, pubkey: null });
    }, [postToParent, wnjPubkey, rejectAllConfirmations]);

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
        saveAutoApproveKinds(parentOrigin, kinds);
    }, [parentOrigin]);

    const handleEncryptBackup = useCallback((password: string) => {
        const pk = privateKeyRef.current;
        if (!pk) throw new Error('Not authenticated');
        return encryptKeyBackup(pk, password);
    }, []);

    const handleBackedUp = useCallback((method: BackupMethod) => {
        const pk = privateKeyRef.current;
        if (!pk || !keyInfo) return;
        setBackupAsk(false);
        recordBackup(pk, keyInfo.publicKeyHex, method, publishRelays);
    }, [keyInfo, publishRelays]);

    const handleBackupLater = useCallback(() => {
        if (keyInfo) snoozeBackupPrompt(keyInfo.publicKeyHex);
        setBackupAsk(false);
    }, [keyInfo]);

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
    // Web3Auth's modal is open and draws its own UI over the iframe; under that
    // sheet, offer the parent page's Nostr signer (if any) and link the library
    // (unless the host page turned the link off).
    if (view === 'connecting') {
        return nostrSigner || poweredBy
            ? <NostrSignerCard kind={nostrSigner} poweredBy={poweredBy} onClick={handleNostrSigner} onHeight={handleSignerCardHeight} />
            : null;
    }

    if (view === 'confirm' && pendingConf?.evolustr) {
        return (
            <EvolustrPromptView
                prompt={pendingConf.evolustr}
                origin={parentOrigin}
                waiting={pendingConf.waiting}
                onAnswer={handleEvolustrAnswer}
            />
        );
    }

    if (view === 'confirm' && pendingConf) {
        return (
            <ConfirmView
                confirmation={pendingConf}
                origin={parentOrigin}
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
                onEncrypt={handleEncryptBackup}
                onBackedUp={handleBackedUp}
                onBack={() => setView('profile')}
                shared={shared}
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
                origin={parentOrigin}
                isWnjMode={!!wnjPubkey}
                shared={shared}
                backupAsk={backupAsk}
                onBackupLater={handleBackupLater}
                onSaveProfile={handleSaveProfile}
                onExportKey={() => setView('export')}
                onLogout={handleLogout}
                onRelaysChange={handleRelaysChange}
                onAutoApproveChange={handleAutoApproveChange}
                onClose={() => setView('avatar')}
                evolustrSection={
                    <EvolustrSettings
                        status={evolustrStatus}
                        apps={evolustrApps}
                        holdsNsec={!wnjPubkey}
                        custody={custodyRef.current}
                        busy={evolustrBusy}
                        message={evolustrMsg}
                        onForgetApp={handleForgetApp}
                        onAddPasskey={handleEvolustrPasskey}
                    />
                }
            />
        );
    }

    // Default: avatar view
    const avatarUrl = userProfile.picture || DEFAULT_AVATAR;
    return <AvatarView avatarUrl={avatarUrl} attention={backupAsk} onClick={() => setView('profile')} />;
}
