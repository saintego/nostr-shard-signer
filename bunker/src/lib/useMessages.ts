// React access to the signer's messages in the resolved language (i18n.ts).
import { createContext, useContext } from 'react';
import { type Locale, type MessagesDef, messagesFor } from './i18n';

export const LocaleContext = createContext<Locale>('en');

export function useMessages<T extends Record<string, string>>(def: MessagesDef<T>): T {
  return messagesFor(def, useContext(LocaleContext));
}
