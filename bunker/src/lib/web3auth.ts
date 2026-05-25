import { Web3Auth, WEB3AUTH_NETWORK } from "@web3auth/modal";
import { getPublicKey } from "nostr-tools";
import { nsecEncode, npubEncode } from "nostr-tools/nip19";
import { hexToBytes } from "./hex";

export interface KeyMaterial {
  privateKeyBytes: Uint8Array;
  publicKeyHex: string;
  nsecStr: string;
  npubStr: string;
}

export async function initWeb3Auth(clientId: string): Promise<Web3Auth> {
  const instance = new Web3Auth({
    clientId,
    web3AuthNetwork: WEB3AUTH_NETWORK.SAPPHIRE_MAINNET,
    uiConfig: {
      loginMethodsOrder: ["google", "apple", "twitter", "email_passwordless"],
    },
  });
  await instance.init();
  return instance;
}

/** Login with a specific social provider, bypassing the Web3Auth modal popup. */
export async function loginWith(
  web3auth: Web3Auth,
  provider: string,
): Promise<void> {
  // In Web3Auth v10 the adapter name changed from 'openlogin' to 'auth'.
  // The TypeScript typings for AuthLoginParams omit loginProvider in v10's public
  // interface, but the runtime still accepts it — cast to suppress the error.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await web3auth.connectTo("auth", { loginProvider: provider } as any);
}

/** Extract and validate the raw secp256k1 private key from the Web3Auth session. */
export async function extractKey(web3auth: Web3Auth): Promise<KeyMaterial> {
  if (!web3auth.provider) throw new Error("No provider after login");

  // provider.request is typed generically; cast to avoid verbose overloading
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rawKey = (await (web3auth.provider as any).request({
    method: "private_key",
  })) as string;

  if (!rawKey || typeof rawKey !== "string")
    throw new Error("Empty private key");
  if (!/^[0-9a-f]{64}$/i.test(rawKey))
    throw new Error("Invalid private key format");

  const privateKeyBytes = hexToBytes(rawKey.toLowerCase());
  const publicKeyHex = getPublicKey(privateKeyBytes);

  return {
    privateKeyBytes,
    publicKeyHex,
    nsecStr: nsecEncode(privateKeyBytes),
    npubStr: npubEncode(publicKeyHex),
  };
}
