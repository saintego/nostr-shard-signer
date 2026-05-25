/** Derives the authoritative parent origin from ancestorOrigins (cannot be spoofed by URL params). */
export function deriveParentOrigin(): string {
  let parentOrigin = "";
  try {
    if (
      typeof document.location.ancestorOrigins !== "undefined" &&
      document.location.ancestorOrigins.length > 0
    ) {
      const ancestor = document.location.ancestorOrigins[0];
      if (ancestor && ancestor !== "null") {
        parentOrigin = new URL(ancestor).origin;
      }
    }
  } catch (_) {}

  // Fallback for Firefox (ancestorOrigins not supported in all contexts)
  if (!parentOrigin && document.referrer) {
    try {
      parentOrigin = new URL(document.referrer).origin;
    } catch (_) {}
  }

  return parentOrigin;
}

/** Returns true only if the page is embedded inside an authorized iframe. */
export function validateEmbedding(parentOrigin: string): boolean {
  if (!parentOrigin) return false;

  // Primary check: ancestorOrigins is authoritative and available in most browsers
  if (typeof document.location.ancestorOrigins !== "undefined") {
    const anc = document.location.ancestorOrigins;
    if (anc.length === 0) return false;          // opened standalone
    if (anc[0] === "null") return false;          // sandboxed without allow-same-origin
    return true;
  }

  // Firefox fallback: ancestorOrigins not supported — verify we're inside a frame
  // window.top !== window.self is true only when inside an iframe
  try {
    return window.top !== window.self;
  } catch (_) {
    // Cross-origin frame access may throw; if so we are definitely in an iframe
    return true;
  }
}
