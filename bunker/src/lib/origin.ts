/** Derives the authoritative parent origin from ancestorOrigins (cannot be spoofed by URL params). */
export function deriveParentOrigin(): string {
  let parentOrigin = '';
  try {
    if (
      typeof document.location.ancestorOrigins !== 'undefined' &&
      document.location.ancestorOrigins.length > 0
    ) {
      const ancestor = document.location.ancestorOrigins[0];
      if (ancestor && ancestor !== 'null') {
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

/** True when the browser can't tell the embedding origin (Firefox): deriveParentOrigin used the referrer. */
export const parentFromReferrer = (): boolean =>
  typeof document.location.ancestorOrigins === 'undefined' ||
  document.location.ancestorOrigins.length === 0;

/** How long the embedding page has to answer SIGNER_PING. */
export const PARENT_PING_MS = 2000;

/**
 * Confirms that the parent really has `origin` (#67). The referrer is the page
 * that navigated this frame, which can differ from the one that embeds it. The
 * browser delivers a message posted with targetOrigin = origin only if the
 * parent has that origin, and nostr-bridge.js answers with the same nonce.
 */
export function confirmParentOrigin(origin: string, timeoutMs = PARENT_PING_MS): Promise<boolean> {
  if (!origin || window.parent === window) return Promise.resolve(false);
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, '0')
  ).join('');
  return new Promise((resolve) => {
    const done = (ok: boolean) => {
      clearTimeout(timer);
      window.removeEventListener('message', onMessage);
      resolve(ok);
    };
    const onMessage = (e: MessageEvent) => {
      const d = e.data as { type?: unknown; nonce?: unknown } | null;
      if (
        e.source === window.parent &&
        e.origin === origin &&
        d?.type === 'SIGNER_PONG' &&
        d.nonce === nonce
      )
        done(true);
    };
    const timer = setTimeout(() => done(false), timeoutMs);
    window.addEventListener('message', onMessage);
    try {
      window.parent.postMessage({ type: 'SIGNER_PING', nonce }, origin);
    } catch (_) {
      done(false);
    }
  });
}

/** Returns true only if the page is embedded inside an authorized iframe. */
export function validateEmbedding(parentOrigin: string): boolean {
  if (!parentOrigin) return false;

  // Primary check: ancestorOrigins is authoritative and available in most browsers
  if (typeof document.location.ancestorOrigins !== 'undefined') {
    const anc = document.location.ancestorOrigins;
    if (anc.length === 0) return false; // opened standalone
    if (anc[0] === 'null') return false; // sandboxed without allow-same-origin
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

/** True for http(s)://localhost and 127.0.0.1 origins (any port). */
export function isLocalhostOrigin(origin: string): boolean {
  try {
    const { hostname } = new URL(origin);
    return hostname === 'localhost' || hostname === '127.0.0.1';
  } catch (_) {
    return false;
  }
}

/**
 * True when the page that embeds the signer is itself inside a frame (#62).
 * A third site framing a registered app would control what the user sees
 * around it, and only the direct parent's origin is checked. Comparing window
 * references is allowed across origins and works in Firefox, which has no
 * ancestorOrigins.
 */
export function isNestedFrame(): boolean {
  try {
    return window.parent !== window.top;
  } catch (_) {
    return true;
  }
}
