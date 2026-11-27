// Which browsers forget unused sites after about a week (#75 day 8): Safari,
// and every browser on iPhone and iPad (they all use Safari's engine).
import { expect, test } from '@playwright/test';
import { forgetsUnusedSites } from '../bunker/src/lib/safariNotice.ts';

const UA = {
  safariMac:
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Safari/605.1.15',
  safariIphone:
    'Mozilla/5.0 (iPhone; CPU iPhone OS 27_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1',
  chromeIphone:
    'Mozilla/5.0 (iPhone; CPU iPhone OS 27_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/158.0 Mobile/15E148 Safari/604.1',
  firefoxIphone:
    'Mozilla/5.0 (iPhone; CPU iPhone OS 27_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/161.0 Mobile/15E148 Safari/605.1.15',
  chromeMac:
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36',
  chromeAndroid:
    'Mozilla/5.0 (Linux; Android 16; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Mobile Safari/537.36',
  edge: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36 Edg/158.0',
  firefoxMac: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.7; rv:161.0) Gecko/20100101 Firefox/161.0',
};

test('Safari and every iPhone browser forget unused sites; Chrome, Edge, Firefox on desktop and Android don’t', () => {
  expect(forgetsUnusedSites(UA.safariMac)).toBe(true);
  expect(forgetsUnusedSites(UA.safariIphone)).toBe(true);
  expect(forgetsUnusedSites(UA.chromeIphone)).toBe(true);
  expect(forgetsUnusedSites(UA.firefoxIphone)).toBe(true);
  expect(forgetsUnusedSites(UA.chromeMac)).toBe(false);
  expect(forgetsUnusedSites(UA.chromeAndroid)).toBe(false);
  expect(forgetsUnusedSites(UA.edge)).toBe(false);
  expect(forgetsUnusedSites(UA.firefoxMac)).toBe(false);
});
