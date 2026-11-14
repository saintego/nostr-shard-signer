/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "true" only in local test builds (scripts/local.sh). */
  readonly VITE_LOCAL_TEST?: string;
  /** Hex public key of the root key that signs the NIP-33 registry. Without a
   *  valid one, only the Web3Auth allowlist can authorize a domain. */
  readonly VITE_ROOT_PUBKEY_HEX?: string;
  /** Comma-separated registry relays; defaults to DEFAULT_REGISTRY_RELAYS. */
  readonly VITE_REGISTRY_RELAYS?: string;
  /** "always": show sensitive prompts in a top-level popup for every page, not
   *  only in shared mode (#62). For self-hosters who want it everywhere. */
  readonly VITE_POPUP_CONFIRM?: string;
  /** Comma-separated origins (or "*.host") with no shared sign-in, added to
   *  SHARED_BLOCKED_ORIGINS in src/lib/shared.ts (#65). */
  readonly VITE_SHARED_BLOCKED_ORIGINS?: string;
}
