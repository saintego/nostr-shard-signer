import './lib/bufferBase64url'; // before anything that loads Evolu (see the file)
import './reset.css'; // the reset's layer; index.html puts it under nostr-post's
import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { confirmParentOrigin, deriveParentOrigin, parentFromReferrer } from './lib/origin';
import { POPUP_PARAM } from './lib/passkeyPopup';
import { PasskeyPopupView } from './components/PasskeyPopupView';
import { CONFIRM_PARAM } from './lib/confirmPopup';
import { ConfirmPopupView } from './components/ConfirmPopupView';
import { GLOBAL_PARAM } from './lib/globalPopup';
import { GlobalSignInPopupView } from './components/GlobalSignInPopupView';
import { TAB_PARAM } from './lib/signerTab';
import { SignerTabView } from './components/SignerTabView';
import './components/GlobalSignInPopup.css';
import { resolveLocale } from './lib/i18n';
import { parseGlobalLogin } from './lib/siteAccount';
import { sweepGlobalSession } from './lib/web3authSession';
import { LocaleContext } from './lib/useMessages';
import './vendor/nostr-post-ui/ui.css';
import './theme.css';
import './styles.css';

const parentOrigin = deriveParentOrigin();

const searchParams = new URLSearchParams(location.search);
const urlParams = {
    clientId: searchParams.get('clientId') ?? '',
    buttonSize: (searchParams.get('buttonSize') ?? 'standard') as 'standard' | 'large_social_grid',
    // registrarUrl, still sent by older bridges, is ignored: the registry key
    // is fixed when the signer is built (#59).
    // Set by the bridge when a Nostr signer is available on the parent page:
    // "1" = window.nostr.js (bunkers), "extension" = a NIP-07 browser extension.
    nostrSigner: ({ '1': 'bunker', extension: 'extension' } as const)[searchParams.get('nostrSigner') ?? ''] ?? null,
    // postMessage protocol version of the bridge; bridges older than the
    // handshake don't send it and speak protocol 1.
    protocol: Number(searchParams.get('protocol') ?? '1'),
    // "0" when the host page turned off the library link (poweredBy: false).
    poweredBy: searchParams.get('poweredBy') !== '0',
    // "1" when the host page turned off shared sign-in (nostrOnly: true).
    nostrOnly: searchParams.get('nostrOnly') === '1',
    // Own-clientId sites: whether to offer the global account (#73 D3, #83).
    globalLogin: parseGlobalLogin(searchParams.get('globalLogin')),
    // "buttons": the signer's own provider buttons instead of Web3Auth's panel (#113).
    signInUi: searchParams.get('signInUi') === 'buttons' ? ('buttons' as const) : undefined,
};

// The passkey popup (src/lib/passkeyPopup.ts) is this same page, top-level.
const isPasskeyPopup = searchParams.get(POPUP_PARAM) === '1';
// The confirmation popup for sensitive prompts in shared mode (src/lib/confirmPopup.ts).
const isConfirmPopup = !isPasskeyPopup && searchParams.get(CONFIRM_PARAM) === '1';
// The global sign-in popup (src/lib/globalPopup.ts, #80); it sweeps by itself.
const isGlobalPopup = !isPasskeyPopup && !isConfirmPopup && searchParams.get(GLOBAL_PARAM) === '1';
// The signer in its own tab (src/lib/signerTab.ts, #90).
const isSignerTab = searchParams.get(TAB_PARAM) === '1';
if (isPasskeyPopup || isConfirmPopup || isGlobalPopup || isSignerTab) document.body.classList.add('popup-page');
// Signer popups run on the signer's own top-level storage, where a global
// sign-in leaves its tokens if its popup closes or crashes (#73 D23, #79).
if (isPasskeyPopup || isConfirmPopup) void sweepGlobalSession();

// The page may ask for a language; the signer uses it only if it has that
// language's text (lib/i18n.ts). Popups get the same parameter.
const locale = resolveLocale(searchParams.get('locale'), navigator.languages ?? [navigator.language]);
document.documentElement.lang = locale;

const render = (embedder: string) => ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
        <LocaleContext.Provider value={locale}>
            {isPasskeyPopup ? <PasskeyPopupView /> : isConfirmPopup ? <ConfirmPopupView /> : isGlobalPopup ? <GlobalSignInPopupView /> : isSignerTab ? <SignerTabView /> : <App parentOrigin={embedder} urlParams={urlParams} />}
        </LocaleContext.Provider>
    </React.StrictMode>,
);

// The widget, where the browser gives only the referrer (Firefox): the page
// must confirm it embeds this frame before anything runs (#67). Bridges from
// before the check don't answer, and the signer reports NOT_EMBEDDED.
const isWidget = !isPasskeyPopup && !isConfirmPopup && !isGlobalPopup && !isSignerTab;
if (isWidget && parentOrigin && parentFromReferrer()) void confirmParentOrigin(parentOrigin).then(ok => render(ok ? parentOrigin : ''));
else render(parentOrigin);
