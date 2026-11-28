// The global sign-in window's first step and its working state (#80, #110, #113).
import { useEffect, useState } from 'react';
import { format } from '../lib/i18n';
import { type Choice, PROVIDERS } from '../lib/popupLogin';
import { useMessages } from '../lib/useMessages';
import { globalSignInMessages } from './GlobalSignInMessages';

/** What the window is doing while it works (#110). */
export type Phase = 'login' | 'checking' | 'saving';

/** The first step's offer: Web3Auth's panel (default), or the signer's own buttons (#113). */
export const choicesFor = (ui: 'panel' | 'buttons' | undefined): readonly Choice[] =>
  ui === 'buttons' ? PROVIDERS : ['panel'];

/**
 * The first step: one button opening Web3Auth's panel, or Google, Apple,
 * Facebook and X, each opening the provider's window from the click.
 */
export function SignInChoice({
  choices,
  onSignIn,
}: {
  choices: readonly Choice[];
  onSignIn: (choice: Choice) => void;
}) {
  const m = useMessages(globalSignInMessages);
  const label = (c: Choice) =>
    c === 'panel'
      ? m.signIn
      : { google: m.google, apple: m.apple, facebook: m.facebook, twitter: m.x }[c];
  return (
    <>
      {choices.map((c, i) => (
        <button
          key={c}
          type="button"
          className={`np-button ${i === 0 ? 'np-filled' : 'np-outlined'}`}
          onClick={() => onSignIn(c)}
        >
          {label(c)}
        </button>
      ))}
      <p className="np-hint">{m.providerHint}</p>
    </>
  );
}

/** What the window is doing, with a note once it's slow (#110). */
export function Working({ phase }: { phase: Phase }) {
  const m = useMessages(globalSignInMessages);
  const [slow, setSlow] = useState(false);
  useEffect(() => {
    setSlow(false);
    if (phase === 'login') return;
    const timer = setTimeout(() => setSlow(true), 6000);
    return () => clearTimeout(timer);
  }, [phase]);
  const text = { login: m.phaseLogin, checking: m.phaseChecking, saving: m.phaseSaving }[phase];
  return (
    <>
      <p className="np-loading" aria-live="polite">
        {text}
      </p>
      {slow && <p className="np-hint">{m.slowHint}</p>}
    </>
  );
}

/**
 * Under a step: an error with the way back (to the account screen it came
 * from, else the start), or Back to the start from a question.
 */
export function StepFooter({
  step,
  reason,
  busy,
  toAccount,
  onBack,
}: {
  step: string;
  reason: string;
  busy: boolean;
  toAccount: boolean;
  onBack: () => void;
}) {
  const m = useMessages(globalSignInMessages);
  if (step === 'failed')
    return (
      <>
        <p className="np-message np-error">{format(m.failed, { reason })}</p>
        <button type="button" className="np-button np-filled" onClick={onBack}>
          {toAccount ? m.back : m.retry}
        </button>
      </>
    );
  if (step !== 'question' && step !== 'unlinked') return null;
  return (
    <button type="button" className="np-button np-text" disabled={busy} onClick={onBack}>
      {m.back}
    </button>
  );
}
