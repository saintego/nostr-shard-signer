/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "true" only in local test builds (scripts/local.sh). */
  readonly VITE_LOCAL_TEST?: string;
  /** Hex public key of the root key that signs the NIP-33 registry. Without a
   *  valid one, only the Web3Auth allowlist can authorize a domain. */
  readonly VITE_ROOT_PUBKEY_HEX?: string;
  /** Comma-separated registry relays; defaults to DEFAULT_REGISTRY_RELAYS. */
  readonly VITE_REGISTRY_RELAYS?: string;
}
