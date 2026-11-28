// Text of TrustSetting (English defaults, lib/i18n.ts). {site} is the site's host.
import { defineMessages } from '../lib/i18n';

export const trustSettingMessages = defineMessages('trustSetting', {
  title: 'Changes to your lists and app data',
  ask: '{site} replaces your lists, bookmarks and app data without asking only if it wrote the version that’s there now. Otherwise you’re asked.',
  trusted:
    '{site} may replace your lists, bookmarks and app data without asking, even when another app wrote them last.',
  trust: 'Trust {site}',
  trustHint:
    'Only for a site you use as your main app. Removing list entries, mute lists and deletions still ask.',
  untrust: 'Ask again',
});
