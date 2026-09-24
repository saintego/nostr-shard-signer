import { useEffect, useRef, useState } from 'react';

// Web3Auth's sheet ends with 24px of empty bottom padding; the panel overlaps it
// so the two read as one sheet.
const OVERLAP = 24;
const SHIFTED_CLASS = 'w3a-shifted';

type Fit = 'full' | 'compact' | 'none';

interface Props {
    onClick: () => void;
    /** Asks the parent to size the iframe so Web3Auth's sheet and the panel both fit. */
    onHeight: (height: number) => void;
}

/**
 * "Nostr signer or bunker" option shown as the bottom part of Web3Auth's login sheet.
 *
 * Web3Auth draws a full-iframe overlay with its sheet anchored to the bottom.
 * We shift that overlay up by the panel's height (see `.w3a-shifted` in
 * styles.css), put the panel underneath, and request an iframe height of
 * sheet + panel. When the parent caps the height (short screens) the caption is
 * dropped, and if even that doesn't fit the panel is hidden and the sheet left
 * untouched, so its close button is never pushed off the top.
 */
export function NostrSignerCard({ onClick, onHeight }: Props) {
    const panelRef = useRef<HTMLDivElement>(null);
    const fullHeightRef = useRef(0); // panel height with caption, once measured
    const [fit, setFit] = useState<Fit>('full');

    useEffect(() => {
        let lastRequested = 0;
        // Web3Auth re-creates its sheet between pages, so poll rather than observe
        // one element.
        const timer = setInterval(() => {
            const sheet = document.querySelector('#w3a-parent-container .w3a-modal-container');
            const panel = panelRef.current;
            if (!sheet || !panel) return;
            const sheetH = sheet.getBoundingClientRect().height;
            if (!sheetH) return;
            if (fit === 'full') fullHeightRef.current = panel.offsetHeight;

            const wanted = Math.ceil(sheetH + fullHeightRef.current - OVERLAP);
            if (wanted !== lastRequested) {
                lastRequested = wanted;
                onHeight(wanted);
            }

            const room = window.innerHeight - sheetH + OVERLAP;
            if (fit === 'full' && panel.offsetHeight > room) setFit('compact');
            else if (fit === 'compact' && panel.offsetHeight > room) setFit('none');
            else if (fit !== 'full' && fullHeightRef.current <= room) setFit('full');

            const shift = fit === 'none' ? 0 : panel.offsetHeight - OVERLAP;
            document.documentElement.style.setProperty('--w3a-shift', `${shift}px`);
        }, 150);
        return () => clearInterval(timer);
    }, [onHeight, fit]);

    useEffect(() => {
        document.body.classList.add(SHIFTED_CLASS);
        return () => {
            document.body.classList.remove(SHIFTED_CLASS);
            document.documentElement.style.removeProperty('--w3a-shift');
        };
    }, []);

    return (
        <div
            ref={panelRef}
            className={'nostr-signer-panel' + (fit === 'compact' ? ' compact' : '')}
            style={{ visibility: fit === 'none' ? 'hidden' : 'visible' }}
        >
            <div className="nostr-signer-or">or</div>
            <button className="nostr-signer-btn" onClick={onClick}>
                <span>Nostr signer or bunker</span>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <circle cx="7.5" cy="15.5" r="5.5" />
                    <path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3" />
                </svg>
            </button>
            <p className="nostr-signer-caption">
                Your own key via Amber, nsec.app, nsecBunker or any NIP-46 bunker
            </p>
        </div>
    );
}
