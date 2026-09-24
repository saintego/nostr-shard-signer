/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "true" only in local test builds (scripts/local.sh). */
  readonly VITE_LOCAL_TEST?: string;
}
