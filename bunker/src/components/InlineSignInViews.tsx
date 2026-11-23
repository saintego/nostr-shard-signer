// The widget's own global sign-in steps (#122): "no account uses this sign-in
// yet", and the hand-over to the sign-in window. Rendered in the widget's sheet.
import { createContext, type ReactNode, useContext, useEffect, useRef } from 'react';
import { format } from '../lib/i18n';
import { useMessages } from '../lib/useMessages';
import { providerName } from './AccountQuestionView';
import { inlineSignInMessages } from './InlineSignInMessages';
import { linkingMessages } from './LinkingMessages';
import './SharedSignInSheet.css';

/** Asks the page for this height (the card's, with its margins), so no empty panel shows (#125). */
export const SheetHeight = createContext<((height: number) => void) | null>(null);

function Sheet({ children }: { children: ReactNode }) {
  const onHeight = useContext(SheetHeight);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el || !onHeight) return;
    let last = 0;
    // The content's height, sent only when it changes (the widget's size is
    // animated, and the text rewraps while it grows).
    const report = () => {
      const style = getComputedStyle(el);
      const margins = Number.parseFloat(style.marginTop) + Number.parseFloat(style.marginBottom);
      const height = Math.ceil(el.scrollHeight + margins);
      if (height === last) return;
      last = height;
      onHeight(height);
    };
    const observer = new ResizeObserver(report);
    observer.observe(el);
    return () => observer.disconnect();
  }, [onHeight]);
  return (
    <div ref={ref} className="shared-sheet np-card" role="dialog">
      {children}
    </div>
  );
}

/** No account uses this sign-in yet: create one here, or link it to another in the window. */
export function InlineNoAccount({
  provider,
  wasUnlinked,
  busy,
  onCreate,
  onOther,
  onCancel,
}: {
  provider: string;
  wasUnlinked: boolean;
  busy: boolean;
  onCreate: () => void;
  onOther: () => void;
  onCancel: () => void;
}) {
  const lm = useMessages(linkingMessages);
  const m = useMessages(inlineSignInMessages);
  return (
    <Sheet>
      <h2 className="np-title">{format(lm.noneTitle, { provider: providerName(provider, lm) })}</h2>
      {wasUnlinked && <p className="np-message np-info">{lm.noneWasUnlinked}</p>}
      <button type="button" className="np-button np-filled" disabled={busy} onClick={onCreate}>
        {lm.createAccount}
      </button>
      <p className="np-hint">{lm.createHint}</p>
      <button type="button" className="np-button np-outlined" disabled={busy} onClick={onOther}>
        {m.madeOther}
      </button>
      <button type="button" className="np-button np-text" disabled={busy} onClick={onCancel}>
        {m.cancel}
      </button>
    </Sheet>
  );
}

/** The window continues from this login; opening it needs this click. */
export function InlineContinue({
  site,
  onContinue,
  onCancel,
}: {
  site: string;
  onContinue: () => void;
  onCancel: () => void;
}) {
  const m = useMessages(inlineSignInMessages);
  return (
    <Sheet>
      <h2 className="np-title">{m.continueTitle}</h2>
      <p className="np-hint">{format(m.continueExplain, { site })}</p>
      <button type="button" className="np-button np-filled" onClick={onContinue}>
        {m.continueButton}
      </button>
      <button type="button" className="np-button np-text" onClick={onCancel}>
        {m.cancel}
      </button>
    </Sheet>
  );
}

/** Wraps a view (the new account's name-and-picture step) in the widget's sheet. */
export const InlineSheet = Sheet;
