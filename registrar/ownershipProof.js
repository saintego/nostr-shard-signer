// Proof that the caller holds a registrant's key (#68): a one-time nonce, bound
// to (clientId, registrant), signed back as a kind-27235 event (NIP-98 style).
// /register and /update both use it.

import { verifyEvent } from 'nostr-tools';

// nonce:{clientId}:{registrantHex}:{nonce} → JSON (CHALLENGES_KV, TTL-bound). One key
// per nonce (#145): phase 1 needs no proof, so a stranger asking for a
// challenge for the same pair mustn't replace the registrant's pending one.
const KV_PREFIX_NONCE = 'nonce:';
export const NONCE_TTL_SEC = 300; // 5 minutes
const PROOF_KIND = 27235;

// clientIds never contain colons (the worker refuses them), so the key is unambiguous.
const nonceKey = (clientId, registrantHex, nonce) =>
  `${KV_PREFIX_NONCE + clientId}:${registrantHex}:${nonce}`;

/** Issues and stores a fresh nonce for (clientId, registrant). */
export async function issueChallenge(env, clientId, registrantHex) {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const nonce = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  await env.CHALLENGES_KV.put(
    nonceKey(clientId, registrantHex, nonce),
    JSON.stringify({ nonce, registrantHex, expiresAt: Date.now() + NONCE_TTL_SEC * 1000 }),
    { expirationTtl: NONCE_TTL_SEC }
  );
  return nonce;
}

/**
 * Checks a signed answer to the challenge for (clientId, registrant), and
 * consumes the nonce when it holds. Returns { ok: true } or { error, status }.
 */
export async function verifyOwnershipProof(env, clientId, registrantHex, nonce, signedEvent) {
  const fail = (error, status = 400) => ({ error, status });
  if (typeof nonce !== 'string' || !/^[0-9a-f]{64}$/.test(nonce))
    return fail('nonce does not match the issued challenge');
  const key = nonceKey(clientId, registrantHex, nonce);
  let record = null;
  try {
    record = JSON.parse((await env.CHALLENGES_KV.get(key)) ?? 'null');
  } catch (_) {}
  if (!record) return fail('No active challenge for this clientId and npub. Request a new one.');
  if (Date.now() > record.expiresAt) {
    await env.CHALLENGES_KV.delete(key);
    return fail('Challenge has expired. Request a new one.', 410);
  }
  if (nonce !== record.nonce) return fail('nonce does not match the issued challenge');

  const { id, pubkey, sig, kind, content, created_at } = signedEvent ?? {};
  if (!id || !pubkey || !sig || kind === undefined || content === undefined || !created_at) {
    return fail(
      'signedEvent is missing required NIP-01 fields (id, pubkey, sig, kind, content, created_at)'
    );
  }
  if (pubkey !== registrantHex)
    return fail('signedEvent is signed by another key than the npub', 403);
  if (kind !== PROOF_KIND) return fail(`signedEvent must be kind ${PROOF_KIND}`);
  const ageSec = Math.floor(Date.now() / 1000) - created_at;
  if (ageSec > NONCE_TTL_SEC || ageSec < -30) {
    return fail('signedEvent created_at is outside the acceptable time window (±5 min)');
  }
  if (content !== record.nonce) return fail('signedEvent content does not match the issued nonce');
  let valid = false;
  try {
    valid = verifyEvent(signedEvent);
  } catch (_) {}
  if (!valid) return fail('signedEvent signature is invalid', 403);

  await env.CHALLENGES_KV.delete(key); // one-time use
  return { ok: true };
}

/** The registrant marker a Web3Auth project owner can add to the allowlist (#68). */
export const REGISTRANT_MARKER_SUFFIX = '.nostr-registrant.invalid';

/**
 * The npubs the project owner named as registrants: allowlist origins of the
 * form https://<npub>.nostr-registrant.invalid. Only the project owner can edit
 * the allowlist, so a marker proves the owner chose that npub.
 */
export function registrantMarkers(origins) {
  const npubs = [];
  for (const origin of origins) {
    const host = origin.replace(/^https:\/\//, '');
    if (host.endsWith(REGISTRANT_MARKER_SUFFIX)) {
      const label = host.slice(0, -REGISTRANT_MARKER_SUFFIX.length);
      if (/^npub1[02-9ac-hj-np-z]{58}$/.test(label)) npubs.push(label);
    }
  }
  return npubs;
}
