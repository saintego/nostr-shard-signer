// Text of WelcomeBackView (English defaults, lib/i18n.ts). {site} is the
// site's host, as the widget verified it.
import { defineMessages } from '../lib/i18n';

export const welcomeBackMessages = defineMessages('welcomeBack', {
  title: 'Welcome back',
  choose: 'Choose the identity to use on {site}.',
  incomplete:
    'Some names and paired sites couldn’t be loaded yet. Your identities are safe; try again later to see everything.',
  unnamed: 'Identity {n}',
  createdOn: 'Created on {site}',
  pairedWith: 'Used on {sites}',
  notPaired: 'Not used on any site yet',
  usedElsewhere: 'Its key was exported or brought in: other apps may hold it.',
  use: 'Use on {site}',
  pairAndUse: 'Pair with {site}',
  create: 'Create a new identity',
  manage: 'Manage',
  // Create (D15)
  createTitle: 'A new identity',
  createExplain:
    'It gets its own npub. Sites can’t tell it belongs to you, unless you use it with your other identities on the same site.',
  labelField: 'A name only you see (optional)',
  useGoogleProfile: 'Use the name and picture of the account you signed in with',
  useGoogleProfileHint: 'They’ll be public on Nostr. Leave this off to stay unlinked.',
  createConfirm: 'Create',
  back: 'Back',
  // Manage
  manageTitle: 'Identities on {site}',
  unpair: 'Unpair from {site}',
  unpairHint: '{site} keeps what it already saw, but can’t sign with it any more.',
  noneLeft: 'No identity is paired with {site} now: you’ll be signed out there.',
  done: 'Done',
});
