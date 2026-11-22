import { PREVIEW } from '../lib/shared';
import { useMessages } from '../lib/useMessages';
import { testVersionNoticeMessages } from './TestVersionNoticeMessages';

/** Preview builds with a test sign-in project (lib/shared.ts): says so wherever users sign in. */
export function TestVersionNotice() {
  const m = useMessages(testVersionNoticeMessages);
  if (!PREVIEW) return null;
  return <p className="np-message np-warning">{m.notice}</p>;
}
