// Text of SharedSignInSheet (English defaults, lib/i18n.ts).
import { defineMessages } from '../lib/i18n';

export const sharedSignInMessages = defineMessages('sharedSignIn', {
  title: 'Sign in',
  google: 'Continue with Google',
  googleHint: 'Opens a sign-in window. Your account works on every site that uses this sign-in.',
  extension: 'Use my Nostr extension',
  bunker: 'Use my Nostr signer or bunker',
  cancel: 'Cancel',
  poweredBy: 'Powered by nostr-shard-signer',
});
