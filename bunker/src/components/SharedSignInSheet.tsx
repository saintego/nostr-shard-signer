import { useMessages } from '../lib/useMessages';
import { sharedSignInMessages } from './SharedSignInMessages';
import './SharedSignInSheet.css';

const LIB_URL = 'https://github.com/saintego/nostr-shard-signer';

interface Props {
  /** The page's own Nostr signer, if any. */
  nostrSigner: 'bunker' | 'extension' | null;
  poweredBy: boolean;
  /** Opens the global sign-in popup: must run in this click. */
  onGoogle: () => void;
  onNostrSigner: () => void;
  onCancel: () => void;
}

/**
 * The sign-in sheet on shared-sign-in sites (#80): the global sign-in (in the
 * signer's popup, opened from the click here) and the page's own Nostr signer.
 */
export function SharedSignInSheet({ nostrSigner, poweredBy, onGoogle, onNostrSigner, onCancel }: Props) {
  const m = useMessages(sharedSignInMessages);
  return (
    <div className="shared-sheet np-card" role="dialog" aria-label={m.title}>
      <h2 className="np-title">{m.title}</h2>
      <button type="button" className="np-button np-filled" onClick={onGoogle}>
        {m.google}
      </button>
      <p className="np-hint">{m.googleHint}</p>
      {nostrSigner && (
        <button type="button" className="np-button np-outlined" onClick={onNostrSigner}>
          {nostrSigner === 'extension' ? m.extension : m.bunker}
        </button>
      )}
      <button type="button" className="np-button np-text" onClick={onCancel}>
        {m.cancel}
      </button>
      {poweredBy && (
        <a className="shared-sheet-lib" href={LIB_URL} target="_blank" rel="noopener noreferrer">
          {m.poweredBy}
        </a>
      )}
    </div>
  );
}
