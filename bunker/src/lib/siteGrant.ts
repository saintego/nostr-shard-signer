// What the global sign-in gives one site (#80, #84): the site's store key and
// the identities paired with it (their keys), plus which one is active. The
// popup sends it to the widget; the widget keeps it in the site's cache.
// Never the login key or the root.

/** At most this many identities are handed to one site. */
export const MAX_SITE_IDENTITIES = 20;
const MAX_LABEL = 100;

export interface GrantedIdentity {
  readonly secretKey: string;
  readonly pubkey: string;
  readonly label: string | null;
  /**
   * Its key also exists outside this site's sign-in: exported, brought over,
   * imported, or opened by a restricted link (D9, D13). Rewrites of its
   * replaceable data and lists then ask.
   */
  readonly usedElsewhere?: true;
}

export interface SiteGrant {
  readonly storeKey: string;
  readonly identities: readonly GrantedIdentity[];
  /** Pubkey of the identity the site uses now (D14). */
  readonly active: string;
}

export const isHex64 = (s: unknown): s is string =>
  typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);

function parseIdentity(value: unknown): GrantedIdentity | null {
  const v = value as Partial<GrantedIdentity> | null;
  if (!v || !isHex64(v.secretKey) || !isHex64(v.pubkey)) return null;
  const label = typeof v.label === 'string' ? v.label.slice(0, MAX_LABEL) : null;
  return {
    secretKey: v.secretKey,
    pubkey: v.pubkey,
    label,
    ...(v.usedElsewhere === true ? { usedElsewhere: true as const } : {}),
  };
}

/** A grant checked field by field (from the popup, or read back from the cache). */
export function parseSiteGrant(value: unknown): SiteGrant | null {
  const v = value as Partial<SiteGrant> | null;
  if (!v || !isHex64(v.storeKey) || !Array.isArray(v.identities) || !isHex64(v.active)) return null;
  if (v.identities.length === 0 || v.identities.length > MAX_SITE_IDENTITIES) return null;
  const identities = v.identities.map(parseIdentity);
  if (identities.some((i) => i === null)) return null;
  const ok = identities as GrantedIdentity[];
  if (new Set(ok.map((i) => i.pubkey)).size !== ok.length || !ok.some((i) => i.pubkey === v.active))
    return null;
  return { storeKey: v.storeKey, identities: ok, active: v.active };
}

/** The active identity of a grant. */
export const activeIdentity = (g: SiteGrant): GrantedIdentity =>
  g.identities.find((i) => i.pubkey === g.active) ?? (g.identities[0] as GrantedIdentity);

/** The same grant with another identity active (switching in the widget). */
export function withActive(g: SiteGrant, pubkey: string): SiteGrant | null {
  return g.identities.some((i) => i.pubkey === pubkey) ? { ...g, active: pubkey } : null;
}
