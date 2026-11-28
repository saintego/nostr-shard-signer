// Safari (and every browser on iPhone and iPad, which use Safari's engine)
// deletes a site's storage after about a week without a visit: the widget's
// device secret and the site's cache go, so the user signs in again (#75,
// day 8). Their account is safe; they're told once, without alarm.

const SEEN_KEY = 'nss_safari_notice_seen';

/** WebKit with Safari's tracking prevention: Safari, and any browser on iOS/iPadOS. */
export function forgetsUnusedSites(userAgent: string): boolean {
  if (!/AppleWebKit/.test(userAgent)) return false;
  // Chrome, Edge, Opera and Android browsers use their own storage rules.
  return !/Chrome\/|Chromium\/|Edg\/|OPR\/|Android/.test(userAgent);
}

/** The notice is due: such a browser, and not yet acknowledged here. */
export function safariNoticeDue(): boolean {
  try {
    return forgetsUnusedSites(navigator.userAgent) && localStorage.getItem(SEEN_KEY) === null;
  } catch {
    return false;
  }
}

/** "Got it". Safari's own wipe brings it back after a week unused, which is when it matters. */
export function dismissSafariNotice(): void {
  try {
    localStorage.setItem(SEEN_KEY, '1');
  } catch {
    // storage blocked: shown again next time
  }
}
