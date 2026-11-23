// Text of AccountTab (English defaults, lib/i18n.ts).
import { defineMessages } from '../lib/i18n';

export const accountTabMessages = defineMessages('accountTab', {
  backUp: 'Back up your account',
  backUpHint: 'Opens the signer’s own window: your master key and a backup file.',
  logOut: 'Log out',
  logOutHint: 'Signs you out on this site only.',
});
