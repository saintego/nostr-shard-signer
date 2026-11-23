// Text of the widget's own global sign-in steps (InlineSignInViews; English
// defaults, lib/i18n.ts). {site} is the site's host.
import { defineMessages } from '../lib/i18n';

export const inlineSignInMessages = defineMessages('inlineSignIn', {
  madeOther: 'I made one with another sign-in',
  continueTitle: 'One more step',
  continueExplain:
    'Choose what {site} gets in the signer’s own window: it shows your account, so it opens where {site} can’t see or cover it.',
  continueButton: 'Continue in the sign-in window',
  cancel: 'Cancel',
});
