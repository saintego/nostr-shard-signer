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
    // Set by the bridge when window.nostr.js is available on the parent page.
    nostrSigner: searchParams.get('nostrSigner') === '1',
};

ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
        <App parentOrigin={parentOrigin} urlParams={urlParams} />
    </React.StrictMode>,
);
