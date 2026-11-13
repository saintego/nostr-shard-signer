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
 * The shared project's clientId for a page, or '' when the page gets no shared
 * sign-in: shared mode is off, the page asked for Nostr-only sign-in, or it
 * passed a clientId of its own. A page that passes the shared clientId itself
 * is in shared mode too, so it can't be held to the registry checks of an own
 * clientId.
 */
export function sharedClientIdFor(pageClientId: string, nostrOnly: boolean): string {
    if (!SHARED_CLIENT_ID || !SHARED_MODE_ON || nostrOnly) return '';
    return !pageClientId || pageClientId === SHARED_CLIENT_ID ? SHARED_CLIENT_ID : '';
}
