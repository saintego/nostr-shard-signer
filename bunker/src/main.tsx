import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { deriveParentOrigin } from './lib/origin';
import './styles.css';

const parentOrigin = deriveParentOrigin();

const searchParams = new URLSearchParams(location.search);
const urlParams = {
    clientId: searchParams.get('clientId') ?? '',
    buttonSize: (searchParams.get('buttonSize') ?? 'standard') as 'standard' | 'large_social_grid',
    registrarUrl: (searchParams.get('registrarUrl') ?? '').replace(/\/$/, ''),
    // Set by the bridge when a Nostr signer is available on the parent page:
    // "1" = window.nostr.js (bunkers), "extension" = a NIP-07 browser extension.
    nostrSigner: ({ '1': 'bunker', extension: 'extension' } as const)[searchParams.get('nostrSigner') ?? ''] ?? null,
};

ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
        <App parentOrigin={parentOrigin} urlParams={urlParams} />
    </React.StrictMode>,
);
