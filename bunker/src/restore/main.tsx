// The /restore page (#73 D10, #87): its own entry, with no Web3Auth and no
// widget code. Opened by the user only: RestoreView refuses frames, and
// windows opened by another page where the browser shows the opener (not for
// links opened with noopener, the default for target="_blank", #145).
import '../lib/bufferBase64url'; // before anything that loads Evolu
import React from 'react';
import ReactDOM from 'react-dom/client';
import { RestoreView } from '../components/RestoreView';
import { resolveLocale } from '../lib/i18n';
import { LocaleContext } from '../lib/useMessages';
import '../vendor/nostr-post-ui/ui.css';
import '../theme.css';
import '../components/GlobalSignInPopup.css';

const locale = resolveLocale(
  new URLSearchParams(location.search).get('locale'),
  navigator.languages
);
const root = document.getElementById('root');
if (root)
  ReactDOM.createRoot(root).render(
    <React.StrictMode>
      <LocaleContext.Provider value={locale}>
        <RestoreView />
      </LocaleContext.Provider>
    </React.StrictMode>
  );
