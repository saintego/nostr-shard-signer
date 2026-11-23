import { format } from '../lib/i18n';
import type { Step } from '../lib/popupFlow';
import { PROVIDERS, type Provider } from '../lib/popupLogin';
import { useMessages } from '../lib/useMessages';
import { linkingMessages } from './LinkingMessages';

/** A provider's name, for the user. */
export const providerName = (provider: string, m: (typeof linkingMessages)['en']) =>
  provider === 'google'
    ? m.google
    : provider === 'apple'
      ? m.apple
      : provider === 'facebook'
        ? m.facebook
        : provider === 'twitter'
          ? m.twitter
          : provider;

interface Props {
  readonly step: Extract<Step, { step: 'question' }>;
  readonly busy: boolean;
  /** Sign in with another provider (the account's own), then link this one: from the click. */
  readonly onProvider: (provider: Provider) => void;
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
  const others = PROVIDERS.filter((p) => p !== step.first.login.provider);
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
          {format(m.signInWith, { provider: providerName(p, m) })}
        </button>
      ))}
      <button type="button" className="np-button np-filled" disabled={busy} onClick={onCreate}>
        {m.createAccount}
      </button>
      <p className="np-hint">{m.createHint}</p>
    </section>
  );
}
