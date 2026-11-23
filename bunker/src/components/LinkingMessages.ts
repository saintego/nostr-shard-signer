// Text of the linking views (AccountQuestionView, RestrictedView, LinkConfirmView,
// LinkedSignIns; English defaults, lib/i18n.ts). {provider} is a provider's name,
// {masked} a masked email or handle, {site} the site's host.
import { defineMessages } from '../lib/i18n';

export const linkingMessages = defineMessages('linking', {
  google: 'Google',
  apple: 'Apple',
  facebook: 'Facebook',
  twitter: 'X',
  email: 'Email',
  phone: 'Phone',
  // Web3Auth's panel (#113): one button instead of one per provider
  signInOther: 'Sign in with another one',
  // After a login with nothing found (review 8, item 1)
  noneTitle: 'No account uses this {provider} sign-in yet',
  noneExplain:
    'Made one with another sign-in? Sign in with it now, and {provider} gets linked to it.',
  noneWasUnlinked: 'This sign-in was unlinked from the account it belonged to.',
  signInWith: 'Sign in with {provider}',
  createAccount: 'Create a new account',
  createHint: 'A new account with new identities. You can link other sign-ins to it later.',
  unknownTitle: 'Couldn’t check right now',
  unknownExplain:
    'Some places that hold your account didn’t answer, so it isn’t safe to create a new one. Try again in a moment.',
  tryAgain: 'Try again',
  bothTitle: 'Which account?',
  bothExplain:
    'This sign-in has an account of its own, and it’s also linked to an account created with {provider} ({masked}).',
  itsOwn: 'Its own account',
  theLinked: 'The account created with {provider}',
  // Through a link
  createdWith: 'This account was created with {provider} ({masked}).',
  recentlyLinked: '{provider} was linked to this account on {date}.',
  unlinkedOn: 'This sign-in was unlinked from its account on {date}. Sign in with another one.',
  // A restricted link (#98)
  restrictedTitle: 'Identities this sign-in opens',
  restrictedExplain:
    'This sign-in is linked to an account created with {provider} ({masked}), and opens only these identities. To manage the account, sign in with {provider}.',
  useOn: 'Use on {site}',
  // Linking (D25, review 8 item 7)
  linkTitle: 'Link {provider} account {masked} to this account?',
  linkWarnFull:
    '{provider} will open every identity of this account, for good: linking can’t be fully undone. Two-factor on one sign-in doesn’t protect the others.',
  linkWarnRestricted:
    '{provider} will open the identities you choose, for good: linking can’t be fully undone.',
  linkPrimary:
    'Your account was created with {provider}. If you lose that account, your other sign-ins keep working only while their links can be found online. Keep your backup.',
  scopeAll: 'All identities',
  scopeSome: 'Only these identities',
  link: 'Link',
  cancel: 'Cancel',
  refusedSame: 'This is the sign-in you’re already using.',
  refusedOwn: 'This sign-in already has its own account. Two accounts can’t be merged yet.',
  refusedElsewhere: 'This sign-in is linked to another account. Unlink it there first.',
  refusedUnknown: 'Couldn’t check this sign-in right now. Try again in a moment.',
  // Manage
  signInsTitle: 'Sign-ins of this account',
  primaryRow: '{provider} ({masked}): created the account; it can’t be unlinked.',
  linkedRow: '{provider} ({masked}), linked on {date}',
  restrictedRow: 'opens {n} identities',
  unlink: 'Unlink',
  unlinkHint:
    'Unlinking isn’t a revocation: whoever has that sign-in and an old copy can still open the account. To cut it off for good, move to new identities.',
  linkAnother: 'Link another sign-in',
});
