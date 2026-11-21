// The trust rule (#73 D13, #85; fix for #61): when a site may sign without
// asking. Pure: the caller fetches the event now at the address, this site's
// records and the decrypted private list entries, and acts on the decision.

export type TrustDecision =
  | { readonly action: 'sign' }
  | { readonly action: 'ask'; readonly reason: AskReason }
  | { readonly action: 'refuse'; readonly reason: RefuseReason };

/**
 * future: dated too far ahead. protected-delete: a deletion (kind 5) aimed at
 * a vault event, or at an address of another key such as a marker or the
 * counter event (#73 D7; such a deletion can't be valid anyway, NIP-09).
 */
export type RefuseReason = 'future' | 'protected-delete';

export type AskReason =
  | 'not-allowlisted'
  | 'always'
  | 'vanish'
  | 'expiration'
  | 'protected'
  | 'used-elsewhere'
  | 'not-last-writer'
  | 'list-removal'
  | 'private-unreadable'
  | 'sensitive-list'
  | 'unknown-current';

/** How far in the future an event's date may be (open question 3 of #73). */
export const FUTURE_SKEW_S = 5 * 60;

/** Always ask: deletes, profile, follows, relay lists, relay and Blossom auth. */
const ALWAYS_ASK = new Set([0, 3, 5, 10002, 22242, 24242]);
/** Request to vanish (NIP-62): its own warning. */
export const VANISH_KIND = 62;
/** Mute list, block lists and follow sets never use the additive rule. */
const SENSITIVE_LISTS = new Set([10000, 10006, 30000]);
/** Low-harm kinds where a replacement that only adds tags is silent (bookmarks). */
const LOW_HARM = new Set([10003, 30003]);
const ADDITIVE_TAGS = new Set(['p', 'e', 'a', 't', 'r', 'word']);

export interface SignRequest {
  readonly kind: number;
  readonly created_at: number;
  readonly tags: readonly (readonly string[])[];
  readonly content: string;
}

export interface CurrentEvent {
  readonly id: string;
  readonly tags: readonly (readonly string[])[];
  readonly content: string;
}

export interface TrustContext {
  /** The identity asked to sign (for deletions aimed at other keys). */
  readonly pubkey?: string;
  /** Whether a `30078` `d` tag is an Evolustr vault's (protected). */
  readonly isProtectedD?: (d: string) => boolean;
  /** Kinds the user lets this site sign without asking (Settings). */
  readonly autoApproveKinds: ReadonlySet<number>;
  /** Evolustr vault events and other protected events (always ask). */
  readonly isProtected: boolean;
  /** NIP-98 uploads to an allowed media host are fine without asking. */
  readonly isAllowedUpload: boolean;
  /** The identity was exported, brought over or imported (D9). */
  readonly usedElsewhere: boolean;
  /** The user chose "Trusted" for this identity and site (D13). */
  readonly trusted: boolean;
  /**
   * The event now at this address on the relays: null if none exists,
   * undefined if the relays didn't answer (treated as "exists").
   */
  readonly current: CurrentEvent | null | undefined;
  /** Id of the event this site signed last at this address. */
  readonly lastSignedId: string | undefined;
  /** Entries this site added to this list itself (`tag:value`). */
  readonly addedBySite: ReadonlySet<string>;
  /**
   * Private entries (decrypted content) of the current and new list, or
   * null when they can't be decrypted. Undefined when the list has none.
   */
  readonly privateEntries?: { readonly before: readonly string[]; readonly after: readonly string[] } | null;
  /** Seconds since 1970. */
  readonly now: number;
}

export const isReplaceable = (kind: number) => kind === 0 || kind === 3 || (kind >= 10000 && kind < 20000);
export const isAddressable = (kind: number) => kind >= 30000 && kind < 40000;
/** NIP-51 lists and sets (the kinds NIP-51 defines, not a range: 30078 is app data). */
const LIST_KINDS = new Set([
  10000, 10001, 10003, 10004, 10005, 10006, 10007, 10009, 10012, 10015, 10020, 10030, 10050, 10101, 10102,
  30000, 30002, 30003, 30004, 30005, 30007, 30015, 30030, 30063, 30267, 31924, 39089, 39092,
]);
export const isList = (kind: number) => LIST_KINDS.has(kind);

/** A list entry as `tag:value`, the unit added and removed. */
export const entryKey = (tag: readonly string[]) => `${tag[0]}:${tag[1] ?? ''}`;

const listEntries = (tags: readonly (readonly string[])[]) =>
  tags.filter((t) => t[0] !== 'd' && t[0] !== 'title' && t[0] !== 'description').map(entryKey);

/** Entries in `before` but not in `after`. */
const removed = (before: readonly string[], after: readonly string[]) => {
  const kept = new Set(after);
  return before.filter((e) => !kept.has(e));
};

/** Entries a request adds: not in the current list. Recorded as "added by this site". */
export function addedEntries(current: CurrentEvent | null | undefined, next: SignRequest): string[] {
  const before = new Set(current ? listEntries(current.tags) : []);
  return listEntries(next.tags).filter((e) => !before.has(e));
}

const onlyAddsTags = (current: CurrentEvent, next: SignRequest) =>
  current.content === next.content &&
  removed(current.tags.map(entryKey), next.tags.map(entryKey)).length === 0 &&
  next.tags.every((t) => current.tags.some((c) => entryKey(c) === entryKey(t)) || ADDITIVE_TAGS.has(t[0] ?? ''));

/** List rules: silent only for additions and removals of entries this site added. */
function listDecision(evt: SignRequest, ctx: TrustContext): TrustDecision {
  if (SENSITIVE_LISTS.has(evt.kind)) return { action: 'ask', reason: 'sensitive-list' };
  if (ctx.current === undefined) return { action: 'ask', reason: 'unknown-current' };
  if (ctx.current) {
    const gone = removed(listEntries(ctx.current.tags), listEntries(evt.tags));
    if (gone.some((e) => !ctx.addedBySite.has(e))) return { action: 'ask', reason: 'list-removal' };
  }
  if (ctx.privateEntries === null) return { action: 'ask', reason: 'private-unreadable' };
  if (ctx.privateEntries) {
    const gone = removed(ctx.privateEntries.before, ctx.privateEntries.after);
    if (gone.some((e) => !ctx.addedBySite.has(e))) return { action: 'ask', reason: 'list-removal' };
  }
  return { action: 'sign' };
}

/** A kind-5 `a` target the signer never lets a site delete (D7, #82). */
function deletesProtected(evt: SignRequest, ctx: TrustContext): boolean {
  if (evt.kind !== 5) return false;
  return evt.tags.some((t) => {
    if (t[0] !== 'a') return false;
    const [kind, pubkey, ...rest] = (t[1] ?? '').split(':');
    if (ctx.pubkey !== undefined && pubkey !== ctx.pubkey) return true;
    return kind === '30078' && (ctx.isProtectedD?.(rest.join(':')) ?? false);
  });
}

/** Requests that ask or are refused whatever the records say. */
function fixedDecision(evt: SignRequest, ctx: TrustContext): TrustDecision | null {
  if (evt.created_at > ctx.now + FUTURE_SKEW_S) return { action: 'refuse', reason: 'future' };
  if (deletesProtected(evt, ctx)) return { action: 'refuse', reason: 'protected-delete' };
  if (evt.kind === VANISH_KIND) return { action: 'ask', reason: 'vanish' };
  if (ALWAYS_ASK.has(evt.kind)) return { action: 'ask', reason: 'always' };
  if (ctx.isProtected) return { action: 'ask', reason: 'protected' };
  if (evt.kind === 27235 && !ctx.isAllowedUpload) return { action: 'ask', reason: 'always' };
  const replaceable = isReplaceable(evt.kind) || isAddressable(evt.kind);
  if (replaceable && evt.tags.some((t) => t[0] === 'expiration')) return { action: 'ask', reason: 'expiration' };
  if (!ctx.autoApproveKinds.has(evt.kind)) return { action: 'ask', reason: 'not-allowlisted' };
  return null;
}

/** Replaceable and addressable data: silent only where this site may replace it. */
function replaceDecision(evt: SignRequest, ctx: TrustContext): TrustDecision {
  if (ctx.usedElsewhere) return { action: 'ask', reason: 'used-elsewhere' };
  if (isList(evt.kind)) return listDecision(evt, ctx);
  if (ctx.trusted || ctx.current === null) return { action: 'sign' };
  if (ctx.current === undefined) return { action: 'ask', reason: 'unknown-current' };
  if (ctx.current.id === ctx.lastSignedId) return { action: 'sign' };
  if (LOW_HARM.has(evt.kind) && onlyAddsTags(ctx.current, evt)) return { action: 'sign' };
  return { action: 'ask', reason: 'not-last-writer' };
}

/** The decision for one sign_event request. */
export function trustDecision(evt: SignRequest, ctx: TrustContext): TrustDecision {
  const fixed = fixedDecision(evt, ctx);
  if (fixed) return fixed;
  return isReplaceable(evt.kind) || isAddressable(evt.kind) ? replaceDecision(evt, ctx) : { action: 'sign' };
}
