// Text of BringOver (English defaults, lib/i18n.ts). {site} is the site's host.
import { defineMessages } from '../lib/i18n';

export const bringOverMessages = defineMessages('bringOver', {
  title: 'Use this account on other sites',
  explain:
    'This account works only on {site}. Add it to your global account to use it on other sites too. {site} keeps the access it has today, and changes to your lists and app data will ask first.',
  action: 'Add to my global account',
  working: 'Waiting for the sign-in window…',
  done: 'Added. On other sites, pair it from “Welcome back”.',
  failed: 'That didn’t work: {reason}',
});
