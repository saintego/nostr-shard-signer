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

export interface Authorization {
  /** Resolves on the first signed registry event that allows the origin (or a
   *  cached positive answer); otherwise with `final`. Fast, but a relay that
   *  missed a later update could still hold a revoked domain. */
  provisional: Promise<boolean>;
  /** The newest event once every relay has answered or `maxWait` passed.
   *  Gate anything that exposes the key (login, session, signing) on this. */
  final: Promise<boolean>;
}

export function checkAuthorization(
  clientId: string,
  origin: string,
  rootPubkeyHex: string,
  registryRelays: string[],
  maxWait = 8000,
): Authorization {
  // Only a positive cached answer is trusted: a domain added after this tab
  // cached the entry must not stay rejected until the tab is closed.
  const cacheKey = `__nbr_${clientId}`;
  let cachedAllows = false;
  const cached = sessionStorage.getItem(cacheKey);
  if (cached) {
    try {
      cachedAllows = checkDomain(JSON.parse(cached) as RegistryContent, origin);
    } catch (_) {}
  }

  let resolveProvisional!: (ok: boolean) => void;
  const provisional = new Promise<boolean>((r) => (resolveProvisional = r));
  if (cachedAllows) resolveProvisional(true);

  const final = new Promise<boolean>((resolve) => {
    const pool = new SimplePool();
    // Only the root key can sign these (the pool verifies signatures), so a
    // relay can withhold the newest version but not forge a newer one: each
    // relay answers with its own latest, and the newest across them wins.
    let newest: { created_at: number; content: RegistryContent } | null = null;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(safety);
      pool.close(registryRelays);
      if (newest) sessionStorage.setItem(cacheKey, JSON.stringify(newest.content));
      const ok = !!newest && checkDomain(newest.content, origin);
      resolveProvisional(ok);
      resolve(ok);
    };
    // onclose fires once every relay sent EOSE, failed, or hit maxWait.
    const safety = setTimeout(finish, maxWait + 1000);
    try {
      pool.subscribeEose(
        registryRelays,
        { authors: [rootPubkeyHex], kinds: [30078], "#d": [clientId], limit: 1 },
        {
          maxWait,
          onevent: (e) => {
            if (e.pubkey !== rootPubkeyHex) return;
            if (newest && newest.created_at >= e.created_at) return;
            try {
              newest = { created_at: e.created_at, content: JSON.parse(e.content) as RegistryContent };
            } catch (_) {
              return;
            }
            if (checkDomain(newest.content, origin)) resolveProvisional(true);
          },
          onclose: finish,
        },
      );
    } catch (_) {
      finish();
    }
  });

  return { provisional, final };
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
