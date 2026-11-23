// The allowed-apps list on the device and in Evolu (#88): how they combine.
import { expect, test } from '@playwright/test';
import { mergeAllowedApps } from '../bunker/src/lib/allowedAppsModel.ts';

test('a second device gets the apps allowed on the first', () => {
  expect(mergeAllowedApps([], [{ appId: 'a', deleted: false }])).toEqual({
    apps: ['a'],
    toAdd: [],
  });
});

test('apps only this device knows join the synced list', () => {
  expect(mergeAllowedApps(['b'], [{ appId: 'a', deleted: false }])).toEqual({
    apps: ['a', 'b'],
    toAdd: ['b'],
  });
});

test('an app forgotten on another device leaves this one too, and is not added back', () => {
  expect(mergeAllowedApps(['a', 'b'], [{ appId: 'a', deleted: true }])).toEqual({
    apps: ['b'],
    toAdd: ['b'],
  });
});
