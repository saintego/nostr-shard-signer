// The canary (#73 D21, #91): before a new global sign-in, the signer reads the
// shared Web3Auth project's public configuration (C15) and pauses shared
// sign-in if someone added a site to its allowlist, or turned key export off.
// A site on that allowlist could run the shared sign-in itself and obtain
// users' keys; the outside monitor (scripts/checkSharedProject.mjs) alerts
// the operator. An unreadable answer fails open: sign-in stays on.

/** Web3Auth's public project configuration (what the SDK itself reads, C15). */
export const configUrl = (clientId: string, network: string) =>
  `https://api.web3auth.io/signer-service/api/v2/configuration?project_id=${encodeURIComponent(
    clientId
  )}&network=${encodeURIComponent(network)}`;

export type CanaryVerdict =
  | { readonly kind: 'ok' }
  | { readonly kind: 'unreadable' }
  | { readonly kind: 'unknown-site'; readonly sites: readonly string[] }
  | { readonly kind: 'key-export-off' };

const norm = (url: string) => url.trim().replace(/\/+$/, '');

/** The verdict for a configuration (parsed JSON), against the expected allowlist. */
export function judgeConfig(config: unknown, expected: readonly string[]): CanaryVerdict {
  const c = config as { whitelist?: { urls?: unknown }; enableKeyExport?: unknown } | null;
  const urls = c?.whitelist?.urls;
  if (!Array.isArray(urls) || typeof c?.enableKeyExport !== 'boolean')
    return { kind: 'unreadable' };
  if (!c.enableKeyExport) return { kind: 'key-export-off' };
  const known = new Set(expected.map(norm));
  const unknown = urls
    .filter((u): u is string => typeof u === 'string')
    .map(norm)
    .filter((u) => !known.has(u));
  return unknown.length ? { kind: 'unknown-site', sites: unknown } : { kind: 'ok' };
}

/** The expected allowlist: the signer's own address (with and without its path), and extras. */
export function expectedSites(signerUrl: string, extras: string): string[] {
  const u = new URL(signerUrl);
  const base = `${u.origin}${u.pathname.replace(/\/[^/]*$/, '')}`;
  return [u.origin, base, ...extras.split(',').filter(Boolean)].map(norm);
}

/** The longest the canary holds up a sign-in; a slower answer is "unreadable". */
const CANARY_MAX_MS = 5000;

/** Reads the configuration and judges it; a network failure is "unreadable". */
export async function checkCanary(
  clientId: string,
  network: string,
  expected: readonly string[],
  fetcher: typeof fetch = fetch
): Promise<CanaryVerdict> {
  try {
    const res = await fetcher(configUrl(clientId, network), {
      credentials: 'omit',
      signal: AbortSignal.timeout(CANARY_MAX_MS),
    });
    if (!res.ok) return { kind: 'unreadable' };
    return judgeConfig(await res.json(), expected);
  } catch {
    return { kind: 'unreadable' };
  }
}
