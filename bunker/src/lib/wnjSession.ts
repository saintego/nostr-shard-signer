// The page's word on which extension or bunker user is signed in (WNJ_SESSION,
// WNJ_DISCONNECT). The page could claim any pubkey (#67): the signer takes it
// only while it holds no key of its own, and only a well-formed one.

const HEX_PUBKEY = /^[0-9a-f]{64}$/;

/** The pubkey the page reports, or null when the signer must ignore it. */
export function acceptedWnjPubkey(
  data: { pubkey?: unknown },
  signerHoldsKey: boolean
): string | null {
  if (signerHoldsKey) return null;
  return typeof data.pubkey === 'string' && HEX_PUBKEY.test(data.pubkey) ? data.pubkey : null;
}
