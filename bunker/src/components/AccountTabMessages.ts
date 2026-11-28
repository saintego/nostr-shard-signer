// Text of AccountTab (English defaults, lib/i18n.ts).
import { defineMessages } from '../lib/i18n';

export const accountTabMessages = defineMessages('accountTab', {
  backUp: 'Back up your account',
  backUpHint: 'Opens the signer’s own window: your master key and a backup file.',
  safariNotice:
    'Safari signs you out of sites unused for a week (on iPhone, every browser does). Your account is safe: just sign in again.',
  safariGotIt: 'Got it',
  logOut: 'Log out',
  logOutHint: 'Signs you out on this site only.',
});
