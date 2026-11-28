// The signer's popups answer only the document that asked (#144). The site can
// navigate the signer's frame while a popup is open; the answer (a sign-in's
// keys, a passkey's PRF output, an approval) must not reach whatever page is
// there by the time it's ready. A same-origin opener's `performance.timeOrigin`
// changes with every new document, so it tells a navigation apart.

/** The opener's current document, or null when it can't be read (another origin, closed). */
export function openerDocument(opener: Window): number | null {
  try {
    return opener.closed ? null : opener.performance.timeOrigin;
  } catch {
    return null;
  }
}

/** True while the opener still shows the document `asked` came from. */
export const sameOpenerDocument = (opener: Window, asked: number | null): boolean =>
  asked !== null && openerDocument(opener) === asked;
