// The sign-in window's state and small helpers (GlobalSignInPopupView.tsx).

import type { GlobalAccount, NewProfile } from '../lib/globalAccount';
import type { GlobalResult } from '../lib/globalPopup';
import type { Step } from '../lib/popupFlow';
import type { PopupLogin } from '../lib/popupLogin';
import type { Phase } from './SignInChoice';

export type Reply = (result: Omit<GlobalResult, 'type' | 'nonce'>) => boolean;
/** The most a step after the provider's login may take before the window says so (#110). */
export const STEP_MAX_MS = 25000;
export type AccountStep = Extract<Step, { step: 'account' }>;

export type State =
  | { step: 'waiting' }
  | { step: 'refused' }
  | { step: 'ready'; site: string }
  | { step: 'working'; site: string; phase: Phase }
  /** A new account: its first identity, with the sign-in account's name and picture or not. */
  | {
      step: 'new-account';
      site: string;
      account: GlobalAccount;
      profile: NewProfile;
      pubkey: string;
    }
  | ({ site: string } & Step)
  /** Before sealing a link: who is being linked (review 8, item 7), or why it can't be. */
  | ({
      step: 'link-confirm';
      site: string;
      candidate: PopupLogin;
      refused: string | null;
      /** The version of an envelope the candidate already has (a link left half-done). */
      after?: number;
    } & Omit<AccountStep, 'step'>)
  | { step: 'failed'; site: string; reason: string }
  | { step: 'done'; site: string; broughtOver?: boolean }
  // After a bring-over: back up, or skip knowingly (#137).
  | (Omit<AccountStep, 'step'> & { step: 'stored-backup'; site: string });

export const hostOf = (origin: string) => {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
};

export const reasonOf = (e: unknown) => (e as Error)?.message ?? String(e);
