import { format } from '../lib/i18n';
import type { Step } from '../lib/popupFlow';
import type { Choice } from '../lib/popupLogin';
import { useMessages } from '../lib/useMessages';
import { linkingMessages } from './LinkingMessages';

/** A provider's name, for the user (Web3Auth's names, #113: others capitalized). */
export const providerName = (provider: string, m: (typeof linkingMessages)['en']) => {
  const known: Record<string, string> = {
    google: m.google,
    apple: m.apple,
    facebook: m.facebook,
    twitter: m.twitter,
    email_passwordless: m.email,
    sms_passwordless: m.phone,
    github: 'GitHub',
    linkedin: 'LinkedIn',
    wechat: 'WeChat',
  };
  return known[provider] ?? provider.charAt(0).toUpperCase() + provider.slice(1);
};

interface Props {
  readonly step: Extract<Step, { step: 'question' }>;
  readonly busy: boolean;
  /** Sign in with another provider (the account's own), then link this one: from the click. */
  readonly onProvider: (choice: Choice) => void;
  /** What to offer: Web3Auth's panel (['panel']) or the signer's provider buttons (#113). */
  readonly choices: readonly Choice[];
  readonly onCreate: () => void;
  readonly onRetry: () => void;
  readonly onChooseOwn: () => void;
  readonly onChooseLinked: () => void;
}

/**
 * After a login (#73 D25, review 8): nothing found ("No account uses this
 * sign-in yet"), couldn't check (no create button), or two accounts to choose.
 */
export function AccountQuestionView({
  step,
  busy,
  onProvider,
  choices,
  onCreate,
  onRetry,
  onChooseOwn,
  onChooseLinked,
}: Props) {
  const m = useMessages(linkingMessages);
  const provider = providerName(step.first.login.provider, m);
  if (step.kind === 'unknown')
    return (
      <section className="welcome-back">
        <h2 className="np-title">{m.unknownTitle}</h2>
        <p>{m.unknownExplain}</p>
        <button type="button" className="np-button np-filled" disabled={busy} onClick={onRetry}>
          {m.tryAgain}
        </button>
      </section>
    );
  if (step.kind === 'both')
    return (
      <section className="welcome-back">
        <h2 className="np-title">{m.bothTitle}</h2>
        <p>
          {format(m.bothExplain, {
            provider: providerName(step.primary.provider, m),
            masked: step.primary.masked,
          })}
        </p>
        <button
          type="button"
          className="np-button np-filled"
          disabled={busy}
          onClick={onChooseLinked}
        >
          {format(m.theLinked, { provider: providerName(step.primary.provider, m) })}
        </button>
        <button
          type="button"
          className="np-button np-outlined"
          disabled={busy}
          onClick={onChooseOwn}
        >
          {m.itsOwn}
        </button>
      </section>
    );
  const others = choices.filter((p) => p !== step.first.login.provider);
  return (
    <section className="welcome-back">
      <h2 className="np-title">{format(m.noneTitle, { provider })}</h2>
      {step.wasUnlinked && <p className="np-message np-info">{m.noneWasUnlinked}</p>}
      <p>{format(m.noneExplain, { provider })}</p>
      {others.map((p) => (
        <button
          key={p}
          type="button"
          className="np-button np-outlined"
          disabled={busy}
          onClick={() => onProvider(p)}
        >
          {p === 'panel' ? m.signInOther : format(m.signInWith, { provider: providerName(p, m) })}
        </button>
      ))}
      <button type="button" className="np-button np-filled" disabled={busy} onClick={onCreate}>
        {m.createAccount}
      </button>
      <p className="np-hint">{m.createHint}</p>
    </section>
  );
}
