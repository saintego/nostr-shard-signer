// Text of IdentitySwitcher (English defaults, lib/i18n.ts).
import { defineMessages } from '../lib/i18n';

export const identitySwitcherMessages = defineMessages('identitySwitcher', {
  title: 'Identities on this site',
  active: 'In use',
  use: 'Use this one',
  unnamed: 'Identity {n}',
  linkable: 'This site can tell that these identities belong to the same person.',
  manage: 'Add or manage identities',
  manageHint:
    'Opens the sign-in window, where you can pair another identity with this site, create one, or unpair one.',
});
