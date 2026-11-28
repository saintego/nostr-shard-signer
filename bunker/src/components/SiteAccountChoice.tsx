import { type ReactNode, useState } from 'react';
import { format } from '../lib/i18n';
import type { Question } from '../lib/siteAccount';
import { useMessages } from '../lib/useMessages';
import { GuardedButton } from './GuardedButton';
import { siteAccountChoiceMessages } from './SiteAccountChoiceMessages';
import { TestVersionNotice } from './TestVersionNotice';
import './SharedSignInSheet.css';

/** What the widget shows after the site's own login (#73 D5, #83). */
export type ChoiceStep =
  | { readonly kind: 'ask'; readonly question: Question }
  | { readonly kind: 'global'; readonly noteFound: boolean };

interface Props {
  readonly step: ChoiceStep;
  /** The site's host. */
  readonly site: string;
  /** Chose the global account: shows "Continue with your global account". */
  readonly onWantGlobal: () => void;
  /** "Continue with your global account": opens the signer's popup, so it must run in this click. */
  readonly onContinueGlobal: () => void;
  /** The account only for this site (the site login itself). */
  readonly onSiteOnly: () => void;
  /** "Not mine": the note isn't the user's; remembered for that note. */
  readonly onNotMine: () => void;
  readonly onCancel: () => void;
}

type Messages = (typeof siteAccountChoiceMessages)['en'];

function Sheet({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="shared-sheet np-card" role="dialog" aria-label={label}>
      {children}
    </div>
  );
}

const titleOf = (q: Question, m: Messages) =>
  ({
    'reuse-or-site': m.reuseOrSite,
    'sign-up-choice': m.signUpTitle,
    'note-found': m.noteFound,
    'note-again': m.noteAgain,
  })[q];

/**
 * Sign up and Sign in choices on sites with their own clientId (D5): an account
 * only for this site, or the global account in the signer's popup. Guarded
 * buttons (#62): the page can't click them for the user.
 */
export function SiteAccountChoice(props: Props) {
  const m = useMessages(siteAccountChoiceMessages);
  const [confirming, setConfirming] = useState(false);
  const cancel = (
    <button type="button" className="np-button np-text" onClick={props.onCancel}>
      {m.cancel}
    </button>
  );

  if (props.step.kind === 'global')
    return (
      <Sheet label={m.continueGlobal}>
        <TestVersionNotice />
        {props.step.noteFound && <p className="np-message np-info">{m.noteFoundGlobal}</p>}
        <GuardedButton
          type="button"
          className="np-button np-filled"
          onClick={props.onContinueGlobal}
        >
          {m.continueGlobal}
        </GuardedButton>
        <p className="np-hint">{m.sameSignIn}</p>
        {cancel}
      </Sheet>
    );

  if (confirming)
    return (
      <Sheet label={m.confirmSiteOnly}>
        <p>{m.confirmSiteOnly}</p>
        <GuardedButton type="button" className="np-button np-outlined" onClick={props.onSiteOnly}>
          {m.confirm}
        </GuardedButton>
        <button type="button" className="np-button np-text" onClick={() => setConfirming(false)}>
          {m.back}
        </button>
      </Sheet>
    );

  return (
    <AskStep
      {...props}
      question={props.step.question}
      m={m}
      cancel={cancel}
      onConfirm={() => setConfirming(true)}
    />
  );
}

interface AskProps extends Props {
  readonly question: Question;
  readonly m: Messages;
  readonly cancel: ReactNode;
  /** "Only for this site" after a note: confirm first. */
  readonly onConfirm: () => void;
}

/** The question itself: the global account first, except at Sign up (D5: site-only is the default). */
function AskStep({
  question: q,
  m,
  site,
  cancel,
  onWantGlobal,
  onSiteOnly,
  onNotMine,
  onConfirm,
}: AskProps) {
  const globalFirst = q !== 'sign-up-choice';
  const option = (global: boolean, first: boolean) => (
    <>
      <GuardedButton
        type="button"
        className={`np-button ${first ? 'np-filled' : 'np-outlined'}`}
        onClick={global ? onWantGlobal : q === 'note-again' ? onConfirm : onSiteOnly}
      >
        {global ? (q === 'note-found' ? m.signInInstead : m.useGlobal) : m.siteOnly}
      </GuardedButton>
      <p className="np-hint">{format(global ? m.globalHint : m.siteOnlyHint, { site })}</p>
    </>
  );
  return (
    <Sheet label={titleOf(q, m)}>
      <h2 className="np-title">{titleOf(q, m)}</h2>
      {option(globalFirst, true)}
      {q !== 'note-found' && option(!globalFirst, false)}
      {(q === 'note-found' || q === 'note-again') && (
        <button type="button" className="np-button np-text" onClick={onNotMine}>
          {m.notMine}
        </button>
      )}
      {cancel}
    </Sheet>
  );
}
