import { useMessages } from '../lib/useMessages';
import { storedBackupMessages } from './StoredBackupMessages';

/**
 * After "Use this account on other sites" (D9): the key brought over exists
 * only in the global list, on Evolu's relay, which may be wiped (#137). The
 * window reports success only after a backup or an explicit skip.
 */
export function StoredBackupView({
  onBackUp,
  onSkip,
}: {
  onBackUp: () => void;
  onSkip: () => void;
}) {
  const m = useMessages(storedBackupMessages);
  return (
    <section className="welcome-back">
      <h2 className="np-title">{m.title}</h2>
      <p className="np-message np-warning">{m.explain}</p>
      <button type="button" className="np-button np-filled" onClick={onBackUp}>
        {m.backUp}
      </button>
      <button type="button" className="np-button np-text" onClick={onSkip}>
        {m.skip}
      </button>
    </section>
  );
}
