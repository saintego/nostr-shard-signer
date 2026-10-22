// Which signing requests run without a confirmation prompt, per host site.
//
// Ordinary public content (notes, reactions, wiki pages, lists, calendar
// events…) is signed without asking by default: a wrong one can be fixed by
// publishing again, and prompting for every step of a multi-event action
// teaches users to click Approve without reading. Users can turn each group
// off in Settings. Kinds that replace data the user built up elsewhere
// (profile, follows, relays), deletions and decrypts always ask.

export interface KindGroup {
  kinds: number[];
  label: string;
  defaultOn: boolean;
}

// The groups users can toggle in Settings, in display order.
export const KIND_GROUPS: KindGroup[] = [
  { kinds: [1], label: "Short notes (kind 1)", defaultOn: true },
  { kinds: [7], label: "Reactions (kind 7)", defaultOn: true },
  { kinds: [1111], label: "Comments (kind 1111)", defaultOn: true },
  { kinds: [30818], label: "Wiki articles (kind 30818)", defaultOn: true },
  { kinds: [10003, 30003], label: "Bookmarks (kinds 10003, 30003)", defaultOn: true },
  { kinds: [31922, 31923], label: "Calendar events (kinds 31922, 31923)", defaultOn: true },
  { kinds: [30078], label: "App data (kind 30078)", defaultOn: true },
  { kinds: [27235], label: "Media uploads to nostr.build (kind 27235)", defaultOn: true },
  { kinds: [6], label: "Reposts (kind 6)", defaultOn: false },
  { kinds: [42], label: "Channel messages (kind 42)", defaultOn: false },
];

export const DEFAULT_AUTO_APPROVE_KINDS = KIND_GROUPS.filter((g) => g.defaultOn).flatMap((g) => g.kinds);

// Replace the user's profile, follows or relay list, or delete events: a site
// publishing an empty or stale copy silently wipes data, so these always ask.
const ALWAYS_CONFIRM_KINDS = new Set([0, 3, 5, 10002]);

// Kind 27235 (NIP-98) is an HTTP login token for the URL in its `u` tag. Signed
// blindly, a site could act as the user on any service, so only these media
// hosts (and their subdomains) are approved without asking.
const MEDIA_UPLOAD_HOSTS = ["nostr.build"];

function isMediaUploadAuth(evt: { tags?: unknown }): boolean {
  const tags = Array.isArray(evt.tags) ? evt.tags : [];
  const u = tags.find((t): t is string[] => Array.isArray(t) && t[0] === "u");
  if (!u || typeof u[1] !== "string") return false;
  try {
    const url = new URL(u[1]);
    if (url.protocol !== "https:") return false;
    return MEDIA_UPLOAD_HOSTS.some((h) => url.hostname === h || url.hostname.endsWith("." + h));
  } catch (_) {
    return false;
  }
}

export function requiresConfirmation(
  method: string,
  params: string[],
  autoApproveKinds: Set<number>,
): boolean {
  if (method === "get_public_key") return false; // the bridge already has it from AUTH_STATE
  if (method === "nip04_decrypt" || method === "nip44_decrypt") return true;
  if (method === "nip04_encrypt") return true; // DM encryption needs explicit consent
  if (method === "nip44_encrypt") return false; // plaintext already known to parent
  if (method === "sign_event") {
    try {
      const evt = JSON.parse(params[0]) as { kind: number; tags?: unknown };
      if (ALWAYS_CONFIRM_KINDS.has(evt.kind)) return true;
      if (evt.kind === 27235 && !isMediaUploadAuth(evt)) return true;
      return !autoApproveKinds.has(evt.kind);
    } catch (_) {
      return true;
    }
  }
  return true; // unknown method — always prompt
}

// ── Persistence ──────────────────────────────────────────────────────────────
// Stored per host site. Browsers that partition third-party storage already
// keep the iframe's localStorage per site; the key makes it so everywhere.

const LEGACY_KEY = "nostr_signer_auto_kinds";
// The kinds the old, site-wide setting could toggle.
const LEGACY_TOGGLEABLE = [1, 6, 7, 42];

function storageKey(origin: string): string {
  return `${LEGACY_KEY}:${origin}`;
}

export function loadAutoApproveKinds(origin: string): Set<number> {
  try {
    const s = localStorage.getItem(storageKey(origin));
    if (s) return new Set(JSON.parse(s) as number[]);
    // Carry over choices made with the old setting: new defaults, minus kinds
    // the user turned off there, plus kinds they turned on.
    const legacy = localStorage.getItem(LEGACY_KEY);
    const kinds = new Set(DEFAULT_AUTO_APPROVE_KINDS);
    if (legacy) {
      const old = new Set(JSON.parse(legacy) as number[]);
      for (const k of LEGACY_TOGGLEABLE) {
        if (old.has(k)) kinds.add(k);
        else kinds.delete(k);
      }
    }
    return kinds;
  } catch (_) {
    return new Set(DEFAULT_AUTO_APPROVE_KINDS);
  }
}

export function saveAutoApproveKinds(origin: string, kinds: Set<number>): void {
  try {
    localStorage.setItem(storageKey(origin), JSON.stringify([...kinds]));
  } catch (_) { /* storage blocked: the choice lasts for this page only */ }
}

// ── Plain-language descriptions for the confirmation prompt ──────────────────

export interface RequestDescription {
  title: string;
  summary?: string;
  /** Shown as a warning: the action can lose data. */
  warning?: string;
}

const KIND_NAMES: Record<number, string> = {
  1: "a note",
  6: "a repost",
  7: "a reaction",
  42: "a channel message",
  1111: "a comment",
  10003: "your bookmarks list",
  30003: "a bookmark set",
  30078: "app data",
  30818: "a wiki article",
  31922: "a calendar event",
  31923: "a calendar event",
  9734: "a zap request",
};

function tagValue(tags: string[][], name: string): string | undefined {
  return tags.find((t) => t[0] === name)?.[1];
}

function preview(text: string, max = 140): string {
  const t = text.replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max) + "…" : t;
}

function hostOf(url: string | undefined): string | undefined {
  try {
    return url ? new URL(url).hostname : undefined;
  } catch (_) {
    return undefined;
  }
}

export function describeRequest(method: string, params: string[]): RequestDescription {
  switch (method) {
    case "nip04_encrypt":
      return { title: "Encrypt a direct message?", summary: "The app will send it as you." };
    case "nip04_decrypt":
    case "nip44_decrypt":
      return { title: "Let the app read a private message?", summary: "The app will see the decrypted text." };
    case "nip44_encrypt":
      return { title: "Encrypt a sealed message?" };
    case "get_public_key":
      return { title: "Share your public key?" };
    case "sign_event":
      break;
    default:
      return { title: "Approve request?", summary: `Method: ${method}` };
  }

  let evt: { kind?: number; content?: string; tags?: string[][] };
  try {
    evt = JSON.parse(params[0]);
  } catch (_) {
    return { title: "Approve event signature?" };
  }
  const kind = evt.kind ?? -1;
  const tags = Array.isArray(evt.tags) ? evt.tags.filter(Array.isArray) : [];
  const content = typeof evt.content === "string" ? evt.content : "";
  const count = (name: string) => tags.filter((t) => t[0] === name).length;

  switch (kind) {
    case 0: {
      let name: string | undefined;
      try { name = (JSON.parse(content) as { name?: string }).name; } catch (_) { /* not JSON */ }
      return {
        title: "Replace your profile?",
        summary: name ? `New name: ${name}` : undefined,
        warning: "This overwrites your Nostr profile everywhere. Fields missing here are lost.",
      };
    }
    case 3:
      return {
        title: "Replace your follow list?",
        summary: `The new list follows ${count("p")} accounts.`,
        warning: "Accounts missing from it are unfollowed.",
      };
    case 10002:
      return {
        title: "Replace your relay list?",
        summary: `The new list has ${count("r")} relays.`,
        warning: "Relays missing from it are removed.",
      };
    case 5: {
      const n = count("e") + count("a");
      return {
        title: n === 1 ? "Delete an event?" : `Delete ${n} events?`,
        summary: content ? `Reason: ${preview(content)}` : undefined,
        warning: "Relays that honour deletions remove them for good.",
      };
    }
    case 27235: {
      const host = hostOf(tagValue(tags, "u"));
      return {
        title: `Sign in to ${host ?? "a web service"} as you?`,
        summary: `${tagValue(tags, "method") ?? "Request"} ${tagValue(tags, "u") ?? ""}`.trim(),
        warning: "The app can use this to act as you on that service.",
      };
    }
  }

  const what = KIND_NAMES[kind] ?? `an event of kind ${kind}`;
  const title = tagValue(tags, "title") ?? tagValue(tags, "name");
  return {
    title: `Publish ${what}?`,
    summary: title ? preview(title) : content ? preview(content) : undefined,
  };
}
