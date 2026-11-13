// Evolustr Signer API host (evolustr SPEC §5.7): this signer gives each app its
// own key for its encrypted data, derived from a master secret M that only the
// signer can open. The protocol lives in @evolustr/signer (vendored, see
// src/vendor/evolustr/VERSION); this file supplies what only this signer knows:
// the user's key or the bridge for signing, where to keep things, and passkeys.
//
// Custody of M:
//   OAuth mode holds the nsec, so M can be wrapped with it ("sk"). But the owner
//   of the Web3Auth clientId can recover the nsec, and with it M and every app
//   key, so the sk wrap is used only after the user agrees to it. Otherwise a
//   signer passkey (on this signer's origin) protects M.
//   Passthrough mode (extension or bunker on the page) has no nsec: a signer
//   passkey is required, and the signer vault event is signed by the extension
//   or bunker through the bridge.

import { verifyEvent } from 'nostr-tools/pure';
import {
    createEvolustrSigner,
    poolRelays,
    webauthnPasskeys,
    type Bytes,
    type ConfirmRequest,
    type EvolustrSigner,
    type NostrEvent,
    type Passkeys,
    type UnsignedEvent,
} from '../vendor/evolustr/evolustr.js';
import { openPasskeyPopup, popupPasskeys } from './passkeyPopup';

export { isProtectedEvent } from '../vendor/evolustr/evolustr.js';
export type { EvolustrSigner, ConfirmRequest };

/** nsite gateways where `<npub>.<gateway>` is the same app on every one of them. */
export const KNOWN_NSITE_GATEWAYS = ['nsite.lol'];


export const isEvolustrMethod = (method: unknown): method is string =>
    typeof method === 'string' && method.startsWith('evolustr_');

// ── Device-local storage ──────────────────────────────────────────────────────
// localStorage in this iframe is partitioned per host site in most browsers, so
// anything here is a per-site, per-device hint. The signer vault on the relays
// is what counts.

const safeGet = (store: Storage, key: string): string | null => {
    try { return store.getItem(key); } catch (_) { return null; }
};
const safeSet = (store: Storage, key: string, value: string | null): void => {
    try {
        if (value === null) store.removeItem(key);
        else store.setItem(key, value);
    } catch (_) { /* storage blocked: lasts for this page only */ }
};

/** How the user wants M protected: by their login's nsec, or by a passkey. */
export type Custody = 'sk' | 'passkey';

const custodyKey = (pubkey: string) => `evolustr_custody:${pubkey}`;
export const loadCustody = (pubkey: string): Custody | null => {
    const v = safeGet(localStorage, custodyKey(pubkey));
    return v === 'sk' || v === 'passkey' ? v : null;
};
export const saveCustody = (pubkey: string, custody: Custody): void => safeSet(localStorage, custodyKey(pubkey), custody);

// Apps the user allowed. Forgetting one makes it ask again; it can't take back
// a key the app already has.
const appsKey = (pubkey: string) => `evolustr_apps:${pubkey}`;
export const loadAllowedApps = (pubkey: string): string[] => {
    try {
        const v = JSON.parse(safeGet(localStorage, appsKey(pubkey)) ?? '[]') as unknown;
        return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
    } catch (_) { return []; }
};
export const saveAllowedApps = (pubkey: string, apps: string[]): void =>
    safeSet(localStorage, appsKey(pubkey), JSON.stringify(apps));

// The unlocked M stays for this tab only (sessionStorage): leaving it in
// localStorage would hand every app key to anyone with the device's storage.
// The signer vault copy is public data and is kept (evolustr #41).
const mKey = (pubkey: string) => `evolustr_m:${pubkey}`;
const vaultKey = (pubkey: string) => `evolustr_signer_vault:${pubkey}`;

const toHex = (b: Bytes) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const fromHex = (s: string): Bytes | null =>
    /^[0-9a-f]{64}$/.test(s) ? new Uint8Array(s.match(/../g)!.map(h => parseInt(h, 16))) : null;

const cache = {
    get: async (pubkey: string) => {
        const v = safeGet(sessionStorage, mKey(pubkey));
        return v === null ? null : fromHex(v);
    },
    set: async (pubkey: string, m: Bytes) => safeSet(sessionStorage, mKey(pubkey), toHex(m)),
    remove: async (pubkey: string) => safeSet(sessionStorage, mKey(pubkey), null),
    getVault: async (pubkey: string) => safeGet(localStorage, vaultKey(pubkey)),
    setVault: async (pubkey: string, json: string) => safeSet(localStorage, vaultKey(pubkey), json),
};

// ── Passkeys ──────────────────────────────────────────────────────────────────
// Inside the iframe when the embedding page grants it (Chromium tells us via the
// permissions policy); otherwise in a popup on this signer's own origin, opened
// from the user's click inside the iframe (SPEC §5.5 rule 5).

interface FeaturePolicy { allowsFeature(feature: string): boolean }

const frameAllows = (feature: string): boolean => {
    const fp = (document as unknown as { featurePolicy?: FeaturePolicy }).featurePolicy;
    try { return fp?.allowsFeature(feature) === true; } catch (_) { return false; }
};

export interface SignerPasskeys {
    readonly passkeys: Passkeys;
    /** Call synchronously from the click that resolves a gesture prompt. */
    readonly onGesture: () => void;
}

export const signerPasskeys = (rpName: string): SignerPasskeys => {
    const frame = webauthnPasskeys({ rpName });
    const inFrame = frameAllows('publickey-credentials-get') && frameAllows('publickey-credentials-create');
    if (inFrame) return { passkeys: frame, onGesture: () => { } };
    return { passkeys: popupPasskeys(frame.rpId), onGesture: openPasskeyPopup };
};

// ── Signing through the bridge (passthrough mode) ────────────────────────────

const SIGN_TIMEOUT_MS = 5 * 60_000;

/**
 * Asks the bridge to sign the signer vault event with the page's extension or
 * bunker. The answer is checked here: the page can refuse, but can't make the
 * signer accept an event the user's key didn't sign.
 */
export const signThroughBridge = (
    post: (msg: Record<string, unknown>) => void,
    pubkey: string,
) => (event: UnsignedEvent): Promise<NostrEvent> =>
    new Promise((resolve, reject) => {
        const requestId = `evs_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
        const done = () => {
            clearTimeout(timer);
            window.removeEventListener('message', listener);
        };
        const timer = setTimeout(() => {
            done();
            reject(new Error('The extension or bunker did not sign in time'));
        }, SIGN_TIMEOUT_MS);
        const listener = (e: MessageEvent) => {
            if (e.source !== window.parent) return;
            const d = e.data as { type?: unknown; requestId?: unknown; event?: unknown; error?: unknown };
            if (d?.type !== 'EVOLUSTR_SIGN_RESULT' || d.requestId !== requestId) return;
            done();
            if (typeof d.error === 'string') return reject(new Error(d.error));
            const signed = d.event as NostrEvent;
            const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
            if (
                !signed || typeof signed !== 'object' ||
                signed.pubkey !== pubkey ||
                signed.kind !== event.kind ||
                signed.created_at !== event.created_at ||
                signed.content !== event.content ||
                !same(signed.tags, event.tags) ||
                !verifyEvent(JSON.parse(JSON.stringify(signed)))
            ) return reject(new Error('The extension or bunker returned an invalid signature'));
            resolve(signed);
        };
        window.addEventListener('message', listener);
        post({ type: 'EVOLUSTR_SIGN', requestId, event });
    });

// ── The signer ────────────────────────────────────────────────────────────────

export interface HostOptions {
    pubkey: string;
    relays: string[];
    /** OAuth mode: the nsec. Passthrough mode: null. */
    getSecretKey: (() => Uint8Array | null) | null;
    /** Passthrough mode: signs through the bridge. */
    sign: (event: UnsignedEvent) => Promise<NostrEvent>;
    custody: () => Custody | null;
    passkeys: Passkeys;
    confirm: (request: ConfirmRequest) => Promise<boolean>;
    requestGesture: (reason: 'unlock' | 'enrollPasskey') => Promise<void>;
}

export const createHostSigner = (o: HostOptions): EvolustrSigner =>
    createEvolustrSigner({
        relays: poolRelays(),
        relayUrls: o.relays,
        // The origin of this signer, the same on every site that embeds it.
        signerKey: location.origin,
        getPublicKey: async () => o.pubkey,
        sign: o.sign,
        ...(o.getSecretKey ? { getSecretKey: o.getSecretKey } : {}),
        // Only with the user's consent (OAuth): see the comment at the top.
        allowSkWrap: () => o.getSecretKey !== null && o.custody() === 'sk',
        passkeys: o.passkeys,
        cache,
        ui: { confirm: o.confirm, requestGesture: o.requestGesture },
        knownNsiteGateways: KNOWN_NSITE_GATEWAYS,
    });
