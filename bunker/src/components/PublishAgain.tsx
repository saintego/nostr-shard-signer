import { useState } from 'react';
import { type BackupEvents, eventsToPublish, POINTERS_FRESH_DAYS } from '../lib/backupEvents';
import { format } from '../lib/i18n';
import { publishToRelay } from '../lib/nostr';
import { publishSpaced, SIGNER_RELAYS } from '../lib/relayPublish';
import { useMessages } from '../lib/useMessages';
import { restoreMessages } from './RestoreMessages';

/**
 * "Publish again" on /restore (#146): sends the backup's signed events back to
 * the relays. They're signed already, so no key is used; a relay holding a
 * newer version keeps it. Old link pointers only when the user asks.
 */
export function PublishAgain({ events, createdAt }: { events: BackupEvents; createdAt: string }) {
  const m = useMessages(restoreMessages);
  const [withOldLinks, setWithOldLinks] = useState(false);
  const [state, setState] = useState<'ready' | 'sending' | { ok: number; count: number }>('ready');
  const days = Math.floor((Date.now() - Date.parse(createdAt)) / 86_400_000);
  const toSend = eventsToPublish(events, createdAt, Date.now(), withOldLinks);
  if (events.events.length + events.pointers.length === 0) return null;

  const send = async () => {
    setState('sending');
    const results = await publishSpaced(toSend, SIGNER_RELAYS, { publishOne: publishToRelay });
    const reached = new Set(results.filter((r) => r.status !== 'failed').map((r) => r.eventId));
    setState({ ok: reached.size, count: toSend.length });
  };

  return (
    <section className="restore-section">
      <h2 className="np-title">{m.publishTitle}</h2>
      <p>{format(m.publishExplain, { count: String(toSend.length) })}</p>
      {days > POINTERS_FRESH_DAYS && events.pointers.length > 0 && (
        <label className="np-checkbox">
          <input
            type="checkbox"
            checked={withOldLinks}
            onChange={(e) => setWithOldLinks(e.target.checked)}
          />
          <span>{format(m.publishOldLinks, { days: String(days) })}</span>
        </label>
      )}
      {typeof state === 'object' ? (
        <p className="np-message np-success">
          {format(m.published, { ok: String(state.ok), count: String(state.count) })}
        </p>
      ) : (
        <button
          type="button"
          className="np-button np-tonal"
          disabled={state === 'sending' || toSend.length === 0}
          onClick={() => void send()}
        >
          {state === 'sending' ? m.publishing : m.publishButton}
        </button>
      )}
    </section>
  );
}
