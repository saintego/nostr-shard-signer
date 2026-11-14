// Makes clicks the user didn't mean to give fail (#62).
//
// The page that embeds the signer owns the iframe element: it can make it
// transparent, cover all but one button, or move it under the cursor. A
// guarded button is disabled
// - for ARM_DELAY_MS after it appears, after the iframe changes size, and after
//   the document becomes visible again;
// - where the browser supports it (IntersectionObserver v2, Chromium), while
//   the browser can't vouch that the button is visible: nothing covers it, and
//   no opacity, filter or transform hides it.
// Other browsers get the delays only. Prompts in a top-level popup (shared mode,
// src/lib/confirmPopup.ts) don't need this: no page can frame or style them.

import { createContext, useContext, useEffect, useState, type RefObject } from 'react';

export const ARM_DELAY_MS = 700;

/** False inside the confirmation popup, which is a top-level window. */
export const ClickGuardContext = createContext(true);

/** IntersectionObserver v2 (`trackVisibility`, `isVisible`) is available. */
export function supportsVisibilityTracking(): boolean {
  return typeof IntersectionObserverEntry !== 'undefined' && 'isVisible' in IntersectionObserverEntry.prototype;
}

/** True once a click on `ref` can be trusted to be the user's. */
export function useClickGuard(ref: RefObject<HTMLElement | null>): boolean {
  const enabled = useContext(ClickGuardContext);
  const [delayed, setDelayed] = useState(enabled);
  const [hidden, setHidden] = useState(enabled && supportsVisibilityTracking());

  useEffect(() => {
    if (!enabled) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const arm = () => {
      setDelayed(true);
      clearTimeout(timer);
      timer = setTimeout(() => setDelayed(false), ARM_DELAY_MS);
    };
    arm();
    // Also fires once right away; resizing the iframe re-arms the delay.
    const resize = new ResizeObserver(arm);
    resize.observe(document.documentElement);
    const onVisibility = () => { if (document.visibilityState === 'visible') arm(); };
    document.addEventListener('visibilitychange', onVisibility);

    let visibility: IntersectionObserver | undefined;
    const el = ref.current;
    if (el && supportsVisibilityTracking()) {
      visibility = new IntersectionObserver(
        entries => {
          const last = entries[entries.length - 1] as IntersectionObserverEntry & { isVisible?: boolean };
          const visible = last?.isVisible === true;
          setHidden(!visible);
          if (visible) arm(); // just uncovered: wait before trusting a click
        },
        { threshold: [1], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
      );
      visibility.observe(el);
    }
    return () => {
      clearTimeout(timer);
      resize.disconnect();
      visibility?.disconnect();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [enabled, ref]);

  return !enabled || (!delayed && !hidden);
}
