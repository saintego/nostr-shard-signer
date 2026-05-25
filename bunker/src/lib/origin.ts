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
  if (typeof document.location.ancestorOrigins !== "undefined") {
    const anc = document.location.ancestorOrigins;
    if (anc.length === 0) return false;
    if (anc[0] === "null") return false; // sandboxed without allow-same-origin
  }
  return true;
}
