import { SimplePool } from "nostr-tools";
import type { RegistryContent } from "../types";

export async function fetchRegistrarConfig(
  registrarUrl: string,
): Promise<{ pubkey?: string; relays?: string[] }> {
  if (!registrarUrl) return {};
  try {
    const res = await fetch(`${registrarUrl}/pubkey`);
    if (!res.ok) return {};
    return (await res.json()) as { pubkey?: string; relays?: string[] };
  } catch (_) {
    return {};
  }
}

export async function isAuthorized(
  clientId: string,
  origin: string,
  rootPubkeyHex: string,
  registryRelays: string[],
): Promise<boolean> {
  // Only a positive cached answer is trusted: a domain added after this tab
  // cached the entry must not stay rejected until the tab is closed.
  const cacheKey = `__nbr_${clientId}`;
  const cached = sessionStorage.getItem(cacheKey);
  if (cached) {
    try {
      if (checkDomain(JSON.parse(cached) as RegistryContent, origin)) return true;
    } catch (_) {}
  }

  const pool = new SimplePool();
  let content: RegistryContent | null = null;
  try {
    const events = await pool.querySync(
      registryRelays,
      { authors: [rootPubkeyHex], kinds: [30078], "#d": [clientId], limit: 1 },
      { maxWait: 8000 },
    );
    // Each relay answers with its own latest version, and a relay that missed
    // an update still holds an older one: use the newest.
    const newest = events
      .filter((e) => e.pubkey === rootPubkeyHex)
      .sort((a, b) => b.created_at - a.created_at)[0];
    if (newest) {
      content = JSON.parse(newest.content) as RegistryContent;
    }
  } catch (_) {
  } finally {
    pool.close(registryRelays);
  }

  if (!content) return false;
  sessionStorage.setItem(cacheKey, JSON.stringify(content));
  return checkDomain(content, origin);
}

function checkDomain(content: RegistryContent, origin: string): boolean {
  const allowed = content.allowed_domains;
  if (!Array.isArray(allowed)) return false;
  const normalize = (d: string) => {
    try {
      return new URL(
        d.startsWith("http") ? d : `https://${d}`,
      ).origin.toLowerCase();
    } catch (_) {
      return d.toLowerCase();
    }
  };
  const target = normalize(origin);
  return allowed.some((d) => normalize(d) === target);
}
