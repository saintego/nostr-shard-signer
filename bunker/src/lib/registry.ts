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
  const cacheKey = `__nbr_${clientId}`;
  const cached = sessionStorage.getItem(cacheKey);
  if (cached) {
    try {
      return checkDomain(JSON.parse(cached) as RegistryContent, origin);
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
    if (events.length > 0 && events[0].pubkey === rootPubkeyHex) {
      content = JSON.parse(events[0].content) as RegistryContent;
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
