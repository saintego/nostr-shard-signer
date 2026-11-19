// Shared mode (#29, #48): pages that pass no clientId get Google/Apple/X
// sign-in through this signer's own Web3Auth project. Every such site gives
// the same account the same npub. Free while donations cover the Web3Auth
// bill; may be limited per site or become paid (#32–#35).
//
// The project's Web3Auth allowlist must list only the signer's origin(s), never
// a site's: any allowlisted origin can run Web3Auth with this clientId and get
// every shared-mode user's key.

/**
 * The shared project's Web3Auth client ID (Sapphire Mainnet). Empty: no shared
 * mode, and pages without a clientId get Nostr-only sign-in as before.
 *
 * Never change it once users have signed in with it: keys are tied to the
 * clientId, so every shared-mode user would get a new, empty identity. To stop
 * offering shared sign-in, set SHARED_MODE_ON to false instead.
 */
export const SHARED_CLIENT_ID = '';

/**
 * Off switch for shared mode that keeps SHARED_CLIENT_ID, so turning it back
 * on gives users the same keys. While off, shared-mode users can't sign in
 * with Google/Apple/X; those who exported their key keep their identity.
 */
export const SHARED_MODE_ON = true;

/** Where users and site owners can fund shared mode. Empty: no link is shown. */
export const SUPPORT_URL = '';

/**
 * Origins that get no shared sign-in (abuse, or at the site's request), as
 * lowercase origins ("https://evil.example") or "*.example.com" for every
 * subdomain of a host. The operator can also block sites without a deploy,
 * through a list signed with the registry root key (src/lib/blocklist.ts).
 * Self-hosted builds can add entries with VITE_SHARED_BLOCKED_ORIGINS
 * (comma-separated).
 */
export const SHARED_BLOCKED_ORIGINS: readonly string[] = [];

const builtInBlocked = (): readonly string[] => [
    ...SHARED_BLOCKED_ORIGINS,
    ...((import.meta.env?.VITE_SHARED_BLOCKED_ORIGINS as string | undefined) ?? '').split(','),
].map(e => e.trim().toLowerCase()).filter(Boolean);

/** True when `origin` matches an entry: the same origin, or a subdomain of a "*.host" entry. */
export function isOriginBlocked(origin: string, entries: readonly string[]): boolean {
    let normalized: string;
    let host: string;
    try {
        const url = new URL(origin);
        normalized = url.origin.toLowerCase();
        host = url.hostname.toLowerCase();
    } catch (_) {
        return false;
    }
    return entries.some(raw => {
        const entry = raw.trim().toLowerCase();
        if (entry.startsWith('*.')) return host.endsWith(entry.slice(1));
        try {
            return new URL(entry).origin === normalized;
        } catch (_) {
            return false;
        }
    });
}

export interface SharedConfig {
    clientId: string;
    on: boolean;
    blocked: readonly string[];
}

/**
 * The shared project's clientId for a page, or '' when the page gets no shared
 * sign-in: shared mode is off, the page asked for Nostr-only sign-in, it passed
 * a clientId of its own, or its origin is blocked. A page that passes the
 * shared clientId itself is in shared mode too, so it can't be held to the
 * registry checks of an own clientId.
 */
export function sharedClientIdForConfig(
    config: SharedConfig,
    pageClientId: string,
    nostrOnly: boolean,
    parentOrigin: string,
): string {
    if (!config.clientId || !config.on || nostrOnly) return '';
    if (pageClientId && pageClientId !== config.clientId) return '';
    return isOriginBlocked(parentOrigin, config.blocked) ? '' : config.clientId;
}

/** What the page would get without the block list: whether it asks for shared sign-in at all. */
export function wantsSharedSignIn(pageClientId: string, nostrOnly: boolean): boolean {
    return sharedClientIdForConfig({ clientId: SHARED_CLIENT_ID, on: SHARED_MODE_ON, blocked: [] }, pageClientId, nostrOnly, '') !== '';
}

export function sharedClientIdFor(pageClientId: string, nostrOnly: boolean, parentOrigin: string): string {
    return sharedClientIdForConfig({ clientId: SHARED_CLIENT_ID, on: SHARED_MODE_ON, blocked: builtInBlocked() }, pageClientId, nostrOnly, parentOrigin);
}
