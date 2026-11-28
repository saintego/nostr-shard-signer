// Text of BackupView (English defaults, lib/i18n.ts). {restore} is the
// signer's restore address.
import { defineMessages } from '../lib/i18n';

export const backupMessages = defineMessages('backup', {
  title: 'Back up your account',
  explain:
    'One master key opens every identity of this account, on every site. If you lose access to your sign-in, it’s the only way back.',
  masterTitle: 'Your master key',
  password: 'Password for the master key',
  repeat: 'The same password again',
  mismatch: 'The passwords don’t match.',
  show: 'Show the master key',
  showPlain: 'Show it without a password',
  plainWarning: 'Without a password, anyone who sees it gets every identity.',
  label:
    'Your master key: keep it like a seed phrase. Restore it only at {restore}, typed in yourself or from a bookmark, never in a site’s widget or a window it opened, and never use it as an account.',
  copy: 'Copy',
  copied: 'Copied',
  wroteDown: 'I wrote down the master key and the restore address together',
  fileTitle: 'A backup file',
  fileExplain:
    'Also keeps your identities’ names and the sites they’re used on. Only your master key, or a signer that holds it, opens it.',
  download: 'Download the backup file',
  share: 'Save it elsewhere (Drive, email…)',
  sameAccount:
    'Keeping it in the same Google account you sign in with doesn’t help if that account is lost or taken over.',
  saved: 'Saved.',
  done: 'Done',
  later: 'Not now',
});
