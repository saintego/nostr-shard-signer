// Text of StoredBackupView (English defaults, lib/i18n.ts).
import { defineMessages } from '../lib/i18n';

export const storedBackupMessages = defineMessages('storedBackup', {
  title: 'Back up the account you brought over',
  explain:
    'Its key is now kept only in your account’s list, which is stored on a sync service that may be reset. Without a backup file, you could lose this account for good.',
  backUp: 'Back up now',
  skip: 'Skip: I may lose this account',
});
