// Text of SiteAccountChoice (English defaults, lib/i18n.ts). {site} is the
// site's host, as the widget verified it.
import { defineMessages } from '../lib/i18n';

export const siteAccountChoiceMessages = defineMessages('siteAccountChoice', {
  reuseOrSite: 'Reuse your global account, or start a new account only for this site?',
  signUpTitle: 'Which account do you want here?',
  siteOnly: 'An account only for this site',
  siteOnlyHint: '{site} can access it.',
  useGlobal: 'Use my global account',
  globalHint: 'Works on every site. The shared sign-in’s operator can access it; {site} can’t.',
  noteFound: 'A note was found that you may already have an account here.',
  signInInstead: 'Sign in with my global account',
  notMine: 'Not mine',
  noteAgain: 'This login has a note that a global account exists.',
  confirmSiteOnly:
    'This login has a note that a global account exists. Are you sure you want an account only for this site?',
  confirm: 'Yes, only for this site',
  back: 'Back',
  continueGlobal: 'Continue with your global account',
  sameSignIn: 'Choose the same sign-in you used for your global account.',
  noteFoundGlobal: 'A note was found: you may already use your global account here.',
  cancel: 'Cancel',
});
