// Text of NewAccountView (English defaults, lib/i18n.ts).
import { defineMessages } from '../lib/i18n';

export const newAccountMessages = defineMessages('newAccount', {
  title: 'Your Nostr account is ready',
  useProfile: 'Use my name and picture from the account I signed in with',
  useProfileHint:
    'They’ll be public on Nostr, so people who know that account may recognize you. Untick to start without them.',
  continue: 'Continue',
});
