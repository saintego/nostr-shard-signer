// Text of EvolustrSettings (English defaults, lib/i18n.ts). {who} is whoShared
// or whoSite.
import { defineMessages } from '../lib/i18n';

export const evolustrSettingsMessages = defineMessages('evolustrSettings', {
  title: 'App data keys',
  intro:
    "Apps that support Evolustr get their own key from this signer, so other apps can't read their data.",
  checking: 'Checking…',
  notSetUp: 'Not set up yet. Apps that support it will ask when they need a key.',
  loginAndPasskey: 'Protected by your login and by a passkey.',
  login: 'Protected by your login.',
  passkey: 'Protected by a passkey.',
  whoShared: 'whoever runs the shared sign-in you used',
  whoSite: "whoever runs this site's Web3Auth project",
  loginRisk:
    '{who} could recover keys protected by your login. Adding a passkey lets you unlock on new devices without that login, but it doesn’t take their access away: for that, apps need new keys, which isn’t possible yet.',
  exposed:
    '{who} could still open your app keys: they were protected by your login before, and adding a passkey doesn’t change them.',
  addPasskey: 'Add a passkey',
  addAnotherPasskey: 'Add another passkey',
  appsHint: 'Apps you allowed on this site (forgetting one makes it ask again):',
  forget: 'Forget',
  forgetLabel: 'Forget {app}',
});
