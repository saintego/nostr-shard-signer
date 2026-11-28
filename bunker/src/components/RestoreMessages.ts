// Text of the /restore page (RestoreView, RestoreIdentities; English defaults, lib/i18n.ts).
import { defineMessages } from '../lib/i18n';

export const restoreMessages = defineMessages('restore', {
  title: 'Restore your Nostr account',
  intro:
    'Bring back the identities of your account from its master key or backup file, and move their keys into another signer (Amber, an extension or a bunker).',
  checkAddress: 'Only use this page at an address you typed in yourself or saved as a bookmark.',
  framed:
    'This page only works in its own tab, opened by you. Close this and type the address yourself.',
  opened:
    'This page was opened by another page. For your safety, close it and type the address yourself.',
  publishTitle: 'Publish your account’s data again',
  publishExplain:
    'This backup holds signed copies of {count} of your account’s Nostr events: app keys, your profile, follows and relay list, and the signer’s own records. If relays lost them, sending them again brings them back. A relay that has a newer version keeps it.',
  publishOldLinks:
    'This backup is {days} days old. Also send its linked sign-ins? If you removed a link after this backup, sending it could bring that link back.',
  publishButton: 'Publish again',
  publishing: 'Sending…',
  published: 'Sent: {ok} of {count} events reached at least one relay.',
  keyTitle: 'With your master key',
  keyField: 'Master key (nsec1… or ncryptsec1…)',
  password: 'Its password',
  open: 'Open',
  fileTitle: 'With a backup file',
  fileField: 'Backup file',
  fileFor: 'This file belongs to the account {npub}.',
  unlockKey: 'Open it with the master key above',
  unlockExtension: 'Open it with the Nostr extension in this browser',
  bunkerField: 'Or a bunker:// address (Amber…)',
  unlockBunker: 'Open it with this bunker',
  working: 'Opening…',
  removeFromSigner:
    'Done with the master key? Remove it from your extension or Amber now: it isn’t an account, and every identity can be derived from it.',
  identitiesTitle: 'Your identities',
  unnamed: 'Identity {n}',
  usedOn: 'Used on {sites}',
  exportKey: 'Export this identity’s key',
  exportPassword: 'Password for the exported key (recommended)',
  show: 'Show the key',
  showPlain: 'Show it without a password',
  copy: 'Copy',
  copied: 'Copied',
  exportHint:
    'Paste it into Amber, your extension or your bunker. This identity is then marked “used elsewhere”: sites ask before changing its data.',
  evolustrWarning:
    'Apps that keep strict app data with Evolustr need their own recovery phrase in another signer: the key alone doesn’t open that data.',
  startOver: 'Start over',
});
