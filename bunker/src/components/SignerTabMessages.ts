// Text of SignerTabView (English defaults, lib/i18n.ts). {site} is the site's host.
import { defineMessages } from '../lib/i18n';

export const signerTabMessages = defineMessages('signerTab', {
  title: 'Nostr signer',
  waiting: 'Connecting to the widget…',
  connected: 'Connected to the widget on {site}',
  connectedHint: 'Requests from {site} show up here while this tab is open.',
  refused: "The widget that opened this isn't the real signer",
  gone: 'The widget closed. You can close this tab.',
  idle: 'No request right now.',
});
