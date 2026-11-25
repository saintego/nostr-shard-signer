export interface UserProfile {
  name?: string;
  picture?: string;
  about?: string;
  lud16?: string;
}

export interface KeyInfo {
  publicKeyHex: string;
  nsecStr: string;
  npubStr: string;
}

/**
 * A prompt from the Evolustr Signer API (src/lib/evolustr.ts). `setup` says
 * what allowing an app also needs: nothing, the user's choice between their
 * login and a passkey (OAuth), or a new passkey.
 */
export type EvolustrPrompt =
  | {
      kind: "appKey";
      appId: string;
      setup: "none" | "choose" | "passkey";
      /** Shared sign-in: the signer's operator, not the site, runs the Web3Auth project (#66). */
      shared?: boolean;
    }
  | { kind: "enrollPasskey" }
  | { kind: "gesture"; reason: "unlock" | "enrollPasskey" | "retry" | "popup" };

/** The user's answer to an Evolustr prompt. */
export type EvolustrAnswer = "allow" | "allow-sk" | "allow-passkey" | "deny";

export interface PendingConfirmation {
  method: string;
  params: string[];
  /** Set for Evolustr prompts, which have their own view. */
  evolustr?: EvolustrPrompt;
  /** How many more confirmations wait behind this one. */
  waiting?: number;
  /** Counts prompts, so each one mounts fresh (its click guard starts over, #62). */
  seq?: number;
}

export type ViewName =
  | "loading"
  | "login"
  | "connecting"
  /** The global sign-in window is open (#80): a button-sized spinner, no Web3Auth sheet. */
  | "signing-in"
  | "avatar"
  | "profile"
  | "export"
  | "confirm"
  | "error";

export type ButtonSize = "standard" | "large_social_grid";

export interface RegistryContent {
  allowed_domains?: string[];
}
