// The Web3Auth project's public configuration, which includes its dashboard
// "Allowlist URLs". The Web3Auth SDK reads the same endpoint during init()
// (fetchProjectConfig in @web3auth/no-modal). Only the project owner can edit
// the allowlist, so a page origin listed there was put there by the owner of
// the clientId. The endpoint is undocumented: if it stops answering as
// expected, callers fall back to the NIP-33 registry.
const CONFIG_URL = "https://api.web3auth.io/signer-service/api/v2/configuration";

export type AllowlistResult =
  | { status: "ok"; origins: string[] }
  | { status: "not_found" }
  | { status: "unavailable"; reason: string };

export async function fetchAllowlist(
  clientId: string,
  network = "sapphire_mainnet",
  timeoutMs = 5000,
): Promise<AllowlistResult> {
  const url = new URL(CONFIG_URL);
  url.searchParams.set("project_id", clientId);
  url.searchParams.set("network", network);
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (res.status === 404) return { status: "not_found" };
    if (!res.ok) return { status: "unavailable", reason: `HTTP ${res.status}` };
    const data = (await res.json()) as { whitelist?: { urls?: unknown } };
    const urls = data.whitelist?.urls;
    if (!Array.isArray(urls)) return { status: "unavailable", reason: "no allowlist in response" };
    return { status: "ok", origins: urls.map(toOrigin).filter((o): o is string => !!o) };
  } catch (e) {
    return { status: "unavailable", reason: (e as Error).message };
  }
}

// Allowlist entries may carry a path ("https://host/app"); the browser only
// reports scheme + host + port as the parent origin.
function toOrigin(entry: unknown): string | null {
  if (typeof entry !== "string") return null;
  try {
    return new URL(entry).origin.toLowerCase();
  } catch (_) {
    return null;
  }
}

export function isAllowlisted(origins: string[], origin: string): boolean {
  return origins.includes(origin.toLowerCase());
}
