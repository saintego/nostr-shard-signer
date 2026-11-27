import { type ReactNode, useState } from 'react';
import { dismissSafariNotice, safariNoticeDue } from '../lib/safariNotice';
import { useMessages } from '../lib/useMessages';
import { accountTabMessages } from './AccountTabMessages';
import './AccountTab.css';

interface Props {
  /** This site's identities and switching (shared), or "Use this account on other sites". */
  readonly identitySection?: ReactNode;
  /** Shared sign-in: the window opens straight at Backup (#87, #132). */
  readonly onBackUp?: () => void;
  readonly onLogout: () => void;
  /** "Open in a new tab" (#90), when offered. */
  readonly extra?: ReactNode;
  /** The signer keeps this site's sign-in in the widget (not an extension or bunker account). */
  readonly keepsSignIn?: boolean;
}

/**
 * The profile panel's first tab (#132): who you are on this site and the
 * account's actions, short enough that Log out is in view without scrolling.
 */
export function AccountTab({
  identitySection,
  onBackUp,
  onLogout,
  extra,
  keepsSignIn = false,
}: Props) {
  const m = useMessages(accountTabMessages);
  const [safari, setSafari] = useState(() => keepsSignIn && safariNoticeDue());
  return (
    <div className="tab-content account-tab">
      {safari && (
        <div className="np-message np-info safari-notice">
          <span>{m.safariNotice}</span>
          <button
            type="button"
            className="np-button np-text np-small"
            onClick={() => {
              dismissSafariNotice();
              setSafari(false);
            }}
          >
            {m.safariGotIt}
          </button>
        </div>
      )}
      {identitySection}
      {onBackUp && (
        <>
          <button type="button" className="np-button np-tonal" onClick={onBackUp}>
            {m.backUp}
          </button>
          <p className="np-hint">{m.backUpHint}</p>
        </>
      )}
      {extra}
      <button type="button" className="np-button np-outlined np-danger" onClick={onLogout}>
        {m.logOut}
      </button>
      <p className="np-hint">{m.logOutHint}</p>
    </div>
  );
}
