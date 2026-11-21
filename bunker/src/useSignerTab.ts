// The widget's side of the signer's own tab (#90), as a hook so App.tsx doesn't grow.
import { useCallback, useState } from 'react';
import { openSignerTab } from './lib/signerTab';

export function useSignerTab(site: string) {
  const [connected, setConnected] = useState(false);
  /** Call from the click. */
  const open = useCallback(() => openSignerTab(site, setConnected), [site]);
  return { connected, open };
}
