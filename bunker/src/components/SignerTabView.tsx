import { useEffect, useState } from 'react';
import { format } from '../lib/i18n';
import { serveSignerTab, type TabStatus } from '../lib/signerTab';
import { useMessages } from '../lib/useMessages';
import { ConfirmPopupView } from './ConfirmPopupView';
import { signerTabMessages } from './SignerTabMessages';

const hostOf = (origin: string) => {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
};

/**
 * The signer in its own tab (#90, #73 D24): the real address in the address
 * bar, the handshake's result, and this site's prompts while it's connected.
 */
export function SignerTabView() {
  const m = useMessages(signerTabMessages);
  const [status, setStatus] = useState<TabStatus>({ state: 'waiting' });
  useEffect(() => serveSignerTab(location.pathname, setStatus), []);
  useEffect(() => {
    document.title = status.state === 'connected' ? format(m.connected, { site: hostOf(status.site) }) : m.title;
  }, [status, m]);

  if (status.state === 'connected') {
    const site = hostOf(status.site);
    return (
      <main className="np-app global-popup">
        <p className="np-message np-success">{format(m.connected, { site })}</p>
        <p className="np-hint">{format(m.connectedHint, { site })}</p>
        <ConfirmPopupView keepOpen />
      </main>
    );
  }
  const text = { waiting: m.waiting, refused: m.refused, gone: m.gone }[status.state];
  const kind = status.state === 'refused' ? 'np-error' : 'np-info';
  return (
    <main className="np-app global-popup">
      <p className={`np-message ${kind}`}>{text}</p>
    </main>
  );
}
