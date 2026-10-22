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

export interface PendingConfirmation {
  method: string;
  params: string[];
  /** How many more confirmations wait behind this one. */
  waiting?: number;
}

export type ViewName =
  | "loading"
  | "login"
  | "connecting"
  | "avatar"
  | "profile"
  | "export"
  | "confirm"
  | "error";

export type ButtonSize = "standard" | "large_social_grid";

export interface RegistryContent {
  allowed_domains?: string[];
}
