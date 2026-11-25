import type { GlobalAccount } from '../lib/globalAccount';
import { format } from '../lib/i18n';
import { useMessages } from '../lib/useMessages';
import { providerName } from './AccountQuestionView';
import { linkingMessages } from './LinkingMessages';

/** How long "X was linked on <date>" stays in Welcome back (review 8, item 7). */
const RECENT_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * In Welcome back: which sign-in created the account (when signed in through
 * a link), and sign-ins linked recently, so a link the user didn't make shows.
 */
export function LinkNotices({
  account,
  createdWith,
}: {
  account: GlobalAccount;
  createdWith?: { provider: string; masked: string } | null;
}) {
  const m = useMessages(linkingMessages);
  const recent = account.links.filter(
    (l) => !l.unlinkedAt && Date.now() - Date.parse(l.linkedAt) < RECENT_MS
  );
  const relisted = account.relistedLink;
  return (
    <>
      {relisted && (
        <p className="np-message np-info">
          {format(m.relisted, {
            provider: providerName(relisted.provider, m),
            masked: relisted.masked,
          })}
        </p>
      )}
      {createdWith && (
        <p className="np-message np-info">
          {format(m.createdWith, {
            provider: providerName(createdWith.provider, m),
            masked: createdWith.masked,
          })}
        </p>
      )}
      {recent.map((l) => (
        <p key={l.pointerPubkey} className="np-hint">
          {format(m.recentlyLinked, {
            provider: providerName(l.provider, m),
            date: l.linkedAt.slice(0, 10),
          })}
        </p>
      ))}
    </>
  );
}
