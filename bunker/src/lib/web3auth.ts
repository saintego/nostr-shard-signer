import { type AuthLoginParams, authConnector, Web3Auth, WEB3AUTH_NETWORK } from "@web3auth/modal";
import { SITE_SESSION, type SessionNames } from "./web3authSession";
import { getPublicKey } from "nostr-tools";
import { nsecEncode, npubEncode } from "nostr-tools/nip19";
import { hexToBytes } from "./hex";

export interface KeyMaterial {
  privateKeyBytes: Uint8Array;
  publicKeyHex: string;
  nsecStr: string;
  npubStr: string;
}

/**
 * Web3Auth's state storage under a prefix, in localStorage or sessionStorage.
 * A class with plain fields (AGENTS.md exception): Web3Auth may copy its
 * options between windows with postMessage, where closures can't go.
 */
class PrefixedStateStorage {
  constructor(
    readonly prefix: string,
    readonly inSession: boolean,
  ) {}
  private get store(): Storage {
    return this.inSession ? sessionStorage : localStorage;
  }
  async get(key: string): Promise<string | null> {
    return this.store.getItem(this.prefix + key);
  }
  async set(key: string, value: string): Promise<void> {
    this.store.setItem(this.prefix + key, value);
  }
  async remove(key: string): Promise<void> {
    this.store.removeItem(this.prefix + key);
  }
}

/** Web3Auth options that give an instance its own names (#79, check C7). */
function sessionOptions(names: SessionNames) {
  if (names === SITE_SESSION) return {};
  const state = new PrefixedStateStorage(names.statePrefix, names.stateIn === "session");
  return {
    // Web3Auth's state (top-level `storage` covers only that).
    storage: { sessionId: state, accessToken: state, refreshToken: state, idToken: state },
    // The tokens: the auth connector's sessionKey renames them. Only plain
    // values here: these settings are posted to Web3Auth's sign-in popup, and
    // custom storage adapters there make Login hang (C16).
    connectors: [authConnector({ connectorSettings: { sessionKey: names.sessionKey } })],
  };
}

export async function initWeb3Auth(clientId: string, names: SessionNames = SITE_SESSION): Promise<Web3Auth> {
  const instance = new Web3Auth({
    clientId,
    web3AuthNetwork: WEB3AUTH_NETWORK.SAPPHIRE_MAINNET,
    uiConfig: {
      // loginMethodsOrder: ["google", "apple", "twitter", "email_passwordless"],
    },
    ...sessionOptions(names),
  });
  await instance.init();
  return instance;
}

/** Login with a specific social provider, bypassing the Web3Auth modal popup. */
export async function loginWith(
  web3auth: Web3Auth,
  provider: string,
): Promise<void> {
  // In Web3Auth v10 the adapter name is 'auth' and the parameter is 'authConnection'
  // (not 'loginProvider' as in v9). The string values match AUTH_CONNECTION enum
  // ("google", "twitter", "apple", "email_passwordless", etc.).
  // Typed as Web3Auth's login params; its own type for "auth" is a union.
  const params: Partial<AuthLoginParams> = { authConnection: provider };
  await web3auth.connectTo("auth", params);
}

/**
 * The active session's provider. Web3Auth v11 moved it from `web3auth.provider`
 * (now write-only, always reads undefined) to `web3auth.connection`.
 */
export function getProvider(web3auth: Web3Auth) {
  return web3auth.connection?.ethereumProvider ?? null;
}

/** Extract and validate the raw secp256k1 private key from the Web3Auth session. */
export async function extractKey(web3auth: Web3Auth): Promise<KeyMaterial> {
  const provider = getProvider(web3auth);
  if (!provider) throw new Error("No provider after login");

  // provider.request is typed for Ethereum methods; "private_key" is Web3Auth's own.
  const request = provider.request as (args: { method: string }) => Promise<unknown>;
  const rawKey = await request({ method: "private_key" });

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
