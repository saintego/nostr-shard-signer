import { useState } from 'react';
import { format } from '../lib/i18n';
import { useMessages } from '../lib/useMessages';
import { bringOverMessages } from './BringOverMessages';
import { GuardedButton } from './GuardedButton';

interface Props {
  /** The site's host. */
  readonly site: string;
  /** Opens the signer's popup and hands it this account's key: call from the click. */
  readonly onBringOver: () => Promise<void>;
}

/**
 * "Use this account on other sites" (#73 D9, #83), for a site-only account on
 * its own site. A guarded click (#62): the page can't press it for the user.
 */
export function BringOver({ site, onBringOver }: Props) {
  const m = useMessages(bringOverMessages);
  const [state, setState] = useState<'idle' | 'working' | 'done' | { failed: string }>('idle');
  const start = () => {
    const pending = onBringOver(); // the popup opens in this click
    setState('working');
    pending.then(
      () => setState('done'),
      (e: unknown) => {
        const reason = (e as Error)?.message ?? String(e);
        setState(/closed|cancel/i.test(reason) ? 'idle' : { failed: reason });
      }
    );
  };
  return (
    <section className="settings-section">
      <h4>{m.title}</h4>
      <p className="settings-hint">{format(m.explain, { site })}</p>
      {state === 'done' ? (
        <p className="np-message np-success">{m.done}</p>
      ) : (
        <GuardedButton
          type="button"
          className="np-button np-outlined np-small"
          disabled={state === 'working'}
          onClick={start}
        >
          {state === 'working' ? m.working : m.action}
        </GuardedButton>
      )}
      {typeof state === 'object' && (
        <p className="np-message np-error">{format(m.failed, { reason: state.failed })}</p>
      )}
    </section>
  );
}
