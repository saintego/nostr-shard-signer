// Reading the key from a Web3Auth session (lib/web3auth.ts).
import { expect, test } from '@playwright/test';
import type { Web3Auth } from '@web3auth/modal';
import { extractKey } from '../bunker/src/lib/web3auth.ts';

const KEY = '11'.repeat(32);

/** Like Web3Auth's provider proxy: `request` forwards to `this.provider`. */
class FakeProviderProxy {
  provider = {
    request: async ({ method }: { method: string }) => (method === 'private_key' ? KEY : null),
  };
  request(args: { method: string }) {
    return this.provider.request(args);
  }
}

test("the key is asked for on Web3Auth's provider itself, not a detached request (v1 regression)", async () => {
  const w3a = { connection: { ethereumProvider: new FakeProviderProxy() } } as unknown as Web3Auth;
  const km = await extractKey(w3a);
  expect(km.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
  expect(Buffer.from(km.privateKeyBytes).toString('hex')).toBe(KEY);
});
