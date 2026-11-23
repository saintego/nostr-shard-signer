// Text of GlobalSignInPopupView (English defaults, lib/i18n.ts). {site} is the
// site's host, as the widget verified it.
import { defineMessages } from '../lib/i18n';

export const globalSignInMessages = defineMessages('globalSignIn', {
  title: 'Sign in to your Nostr account',
  forSite: 'For {site}',
  explain:
    'Your account works on every site that uses this sign-in. Whoever runs this sign-in service can access it; {site} can’t.',
  google: 'Continue with Google',
  apple: 'Continue with Apple',
  facebook: 'Continue with Facebook',
  x: 'Continue with X',
  providerHint: 'Use the one you used before. You can link the others to your account later.',
  waiting: 'Connecting to the site…',
  working: 'Signing in…',
  done: 'Done. You can go back to {site}.',
  broughtOver:
    'Your account from {site} is now in your global account. On other sites, pair it from “Welcome back”.',
  close: 'Close',
  retry: 'Try again',
  failed: 'Sign-in failed: {reason}',
  refused: 'This window can only be opened from the sign-in widget on a site.',
  notSetUp: 'This sign-in isn’t available yet.',
});
