// Text of EvolustrPromptView, English defaults (lib/i18n.ts). Placeholders:
// {site} is the asking page's host, {app} the app's name as the user knows it,
// {count} a number.
import { defineMessages } from '../lib/i18n';

export const evolustrPromptMessages = defineMessages('evolustrPrompt', {
  unlockTitle: 'Unlock your app keys',
  unlockSummary: 'Use your passkey to unlock the keys that protect your app data.',
  unlockButton: 'Unlock',
  createTitle: 'Create a passkey',
  createSummary: 'Your device will ask you to create a passkey for this signer.',
  continueButton: 'Continue',
  retryTitle: 'Try again?',
  retrySummary: "The passkey step didn't finish. Your browser needs one more click to try again.",
  retryButton: 'Try again',
  popupTitle: 'Create the passkey in a separate window',
  popupSummary:
    "Your browser doesn't allow creating it here. A small window of this signer opens for it.",
  popupButton: 'Open the window',
  cancelButton: 'Cancel',
  siteAsks: '{site} asks:',
  enrollTitle: 'Add a passkey for your app keys?',
  enrollSummary:
    'A passkey lets this signer unlock the keys that protect your app data on your other devices too.',
  appKeyTitle: 'Give {app} its own key for your data?',
  appKeySummary:
    "{app} will encrypt its data with a key only it gets. Other apps can't read that data, even with permission to sign or decrypt.",
  chooseQuestion: 'How should this signer protect your app keys?',
  chooseWarning:
    'With your Google, Apple or X login, {who} could also recover these keys. A passkey keeps them with you alone.',
  whoShared: 'whoever runs the shared sign-in you used',
  whoSite: "whoever runs this site's Web3Auth project",
  chooseNote: 'This choice can’t be changed later for data you already have.',
  withLogin: 'With my login',
  withPasskey: 'With a passkey',
  passkeyFirst:
    'First, create a passkey for this signer: it keeps your app keys safe and unlocks them on your other devices.',
  createPasskeyButton: 'Create passkey',
  dontAllow: "Don't allow",
  allow: 'Allow',
  nsiteLabel: 'the nsite {id}…',
  waitingOne: '{count} more request waiting',
  waitingMany: '{count} more requests waiting',
});
