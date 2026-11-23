import { useState } from 'react';
import type { NewProfile } from '../lib/globalAccount';
import { useMessages } from '../lib/useMessages';
import { newAccountMessages } from './NewAccountMessages';
import './WelcomeBack.css';

/**
 * A new account's first identity (D15, chat decision): the sign-in account's
 * name and picture, used unless the user unticks it.
 */
export function NewAccountView({
  profile,
  busy,
  onContinue,
}: {
  profile: NewProfile;
  busy: boolean;
  onContinue: (useProfile: boolean) => void;
}) {
  const m = useMessages(newAccountMessages);
  const [useProfile, setUseProfile] = useState(true);
  return (
    <section className="welcome-back">
      <h2 className="np-title">{m.title}</h2>
      <label className="np-checkbox welcome-profile">
        <input
          type="checkbox"
          checked={useProfile}
          onChange={(e) => setUseProfile(e.target.checked)}
        />
        <span>
          {m.useProfile}
          {profile.name && <strong> {profile.name}</strong>}
          <span className="np-hint">{m.useProfileHint}</span>
        </span>
      </label>
      {profile.picture && useProfile && (
        <img className="new-account-picture" src={profile.picture} alt="" width={64} height={64} />
      )}
      <button
        type="button"
        className="np-button np-filled"
        disabled={busy}
        onClick={() => onContinue(useProfile)}
      >
        {m.continue}
      </button>
    </section>
  );
}
