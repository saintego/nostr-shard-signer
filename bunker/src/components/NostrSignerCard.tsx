import { useEffect, useRef, useState } from 'react';

const GAP = 8; // space between this card and Web3Auth's sheet

interface Props {
    onClick: () => void;
    /** Asks the parent to size the iframe so the card and Web3Auth's sheet both fit. */
    onHeight: (height: number) => void;
}

/**
 * "Nostr signer or bunker" option shown directly above Web3Auth's login sheet.
 *
 * Web3Auth draws a full-iframe, transparent overlay with its sheet anchored to
 * the bottom. We measure the sheet and request an iframe height of card + gap +
 * sheet, so the card sits in the space above the sheet without covering it.
 */
export function NostrSignerCard({ onClick, onHeight }: Props) {
    const cardRef = useRef<HTMLButtonElement>(null);
    const [top, setTop] = useState<number | null>(null);

    useEffect(() => {
        let lastHeight = 0;
        // Web3Auth re-creates its sheet between pages, so poll rather than observe
        // one element.
        const timer = setInterval(() => {
            const sheet = document.querySelector('#w3a-parent-container .w3a-modal-container');
            const card = cardRef.current;
            if (!sheet || !card) return;
            const sheetH = sheet.getBoundingClientRect().height;
            if (!sheetH) return;
            const needed = Math.ceil(card.offsetHeight + GAP + sheetH);
            if (needed !== lastHeight) {
                lastHeight = needed;
                onHeight(needed);
            }
            // If the parent caps the height (short screens), hide the card rather
            // than let it cover the top of the sheet and its close button.
            const t = window.innerHeight - sheetH - GAP - card.offsetHeight;
            setTop(t >= 0 ? t : null);
        }, 150);
        return () => clearInterval(timer);
    }, [onHeight]);

    return (
        <button
            ref={cardRef}
            className="nostr-signer-card"
            style={{ top: top ?? 0, visibility: top === null ? 'hidden' : 'visible' }}
            onClick={onClick}
        >
            <span className="choice-title">Nostr signer or bunker</span>
            <span className="choice-sub">
                Use your own key with Amber, nsec.app, nsecBunker, or any NIP-46
                remote signer.
            </span>
        </button>
    );
}
