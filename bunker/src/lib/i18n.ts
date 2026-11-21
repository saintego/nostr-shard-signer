// The signer's user-facing text, ready for translation (AGENTS.md, User-facing
// text). Each component keeps its English text in a `*Messages.ts` module made
// with `defineMessages`; translations are bundled here, one set per language and
// component. Pages can't supply text: they may only ask for a language
// (`locale`), which is used if the signer has it.

/** Languages the signer has text for. English is complete; others may be partial. */
export const SUPPORTED_LOCALES = ['en'] as const;
export type Locale = string;

type Catalog = Record<string, string>;
const translations = new Map<string, Map<Locale, Partial<Catalog>>>();

/** A component's messages: English defaults, translated by `messagesFor`. */
export interface MessagesDef<T extends Catalog> {
  readonly name: string;
  readonly en: T;
}

export const defineMessages = <T extends Catalog>(name: string, en: T): MessagesDef<T> => ({ name, en });

/** Registers a translation of one component's messages (bundled with the signer). */
export function addTranslation<T extends Catalog>(def: MessagesDef<T>, locale: Locale, text: Partial<T>): void {
  const byLocale = translations.get(def.name) ?? new Map<Locale, Partial<Catalog>>();
  byLocale.set(normalize(locale), text);
  translations.set(def.name, byLocale);
}

/** The messages in `locale`, falling back to English for anything not translated. */
export function messagesFor<T extends Catalog>(def: MessagesDef<T>, locale: Locale): T {
  const t = translations.get(def.name)?.get(normalize(locale)) ?? translations.get(def.name)?.get(base(locale));
  return t ? { ...def.en, ...t } : def.en;
}

/** Replaces `{name}` placeholders. Values are plain text (React escapes them). */
export const format = (text: string, values: Record<string, string | number>): string =>
  text.replace(/\{(\w+)\}/g, (m, k: string) => (k in values ? String(values[k]) : m));

const normalize = (locale: string) => locale.trim().toLowerCase().replace('_', '-');
const base = (locale: string) => normalize(locale).split('-')[0] ?? '';

/**
 * The language to show: the page's `locale` if the signer has it, then the
 * browser's languages, then English. Only a language code is accepted from the
 * page; anything else is ignored.
 */
export function resolveLocale(
  requested: string | null,
  browser: readonly string[],
  available: readonly string[] = SUPPORTED_LOCALES,
): Locale {
  const has = (l: string) => available.includes(normalize(l)) || available.includes(base(l));
  const pick = (l: string) => (available.includes(normalize(l)) ? normalize(l) : base(l));
  if (requested && /^[a-zA-Z]{2,3}([-_][a-zA-Z0-9]{2,8})*$/.test(requested) && has(requested)) return pick(requested);
  for (const l of browser) if (has(l)) return pick(l);
  return 'en';
}
