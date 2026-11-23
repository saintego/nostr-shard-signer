// The canary for the shared project (#91), once per page: before a new global
// sign-in, in the widget and in the sign-in window. Production builds enforce
// it; previews only log it (the devnet test project also lists the check kit
// and production), unless VITE_CANARY=enforce. VITE_SHARED_EXPECTED_ORIGINS
// adds expected allowlist entries (comma-separated).
import { type CanaryVerdict, checkCanary, expectedSites } from './canary';
import { PREVIEW, SHARED_SIGN_IN_CLIENT_ID, SHARED_SIGN_IN_NETWORK } from './shared';

const env = ((import.meta as { env?: Record<string, string | undefined> }).env ?? {}) as Record<
  string,
  string | undefined
>;
const enforce = env.VITE_CANARY === 'enforce' || !PREVIEW;

let verdict: Promise<CanaryVerdict> | null = null;

/** Whether a new global sign-in may start; the reason when it may not. */
export async function sharedSignInAllowed(): Promise<CanaryVerdict> {
  verdict ??= checkCanary(
    SHARED_SIGN_IN_CLIENT_ID,
    SHARED_SIGN_IN_NETWORK,
    expectedSites(location.href, env.VITE_SHARED_EXPECTED_ORIGINS ?? '')
  );
  const v = await verdict;
  if (v.kind === 'unreadable') console.warn('[canary] the shared project could not be read: on');
  if (v.kind === 'unknown-site' || v.kind === 'key-export-off') {
    console.error('[canary] the shared project changed:', v);
    if (!enforce) return { kind: 'ok' };
  }
  return v;
}

/** Thrown when the canary pauses shared sign-in; signInFailure turns it into the message. */
export const CANARY_PAUSED = 'SHARED_SIGN_IN_PAUSED';

/** Throws CANARY_PAUSED when the canary says a new global sign-in mustn't start. */
export async function assertSharedSignInAllowed(): Promise<void> {
  const v = await sharedSignInAllowed();
  if (v.kind === 'unknown-site' || v.kind === 'key-export-off') throw new Error(CANARY_PAUSED);
}
