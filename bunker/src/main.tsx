import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { deriveParentOrigin } from './lib/origin';
import { POPUP_PARAM } from './lib/passkeyPopup';
import { PasskeyPopupView } from './components/PasskeyPopupView';
import { CONFIRM_PARAM } from './lib/confirmPopup';
import { ConfirmPopupView } from './components/ConfirmPopupView';
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
};

// The passkey popup (src/lib/passkeyPopup.ts) is this same page, top-level.
const isPasskeyPopup = searchParams.get(POPUP_PARAM) === '1';
// The confirmation popup for sensitive prompts in shared mode (src/lib/confirmPopup.ts).
const isConfirmPopup = !isPasskeyPopup && searchParams.get(CONFIRM_PARAM) === '1';
if (isPasskeyPopup || isConfirmPopup) document.body.classList.add('popup-page');

ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
        {isPasskeyPopup ? <PasskeyPopupView /> : isConfirmPopup ? <ConfirmPopupView /> : <App parentOrigin={parentOrigin} urlParams={urlParams} />}
    </React.StrictMode>,
);
