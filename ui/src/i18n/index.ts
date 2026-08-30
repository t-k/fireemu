import { en, type MessageKey } from "./en";

export type { MessageKey };

type Params = Record<string, string | number>;

const messages: Record<string, Record<string, string>> = { en };

let current = "en";

/** Selects the active locale (only `en` ships today). */
export const setLocale = (locale: string): void => {
  if (messages[locale]) {
    current = locale;
  }
};

/** The message for `key` with `{name}` placeholders substituted. */
export const t = (key: MessageKey, params?: Params): string => {
  const table = messages[current] ?? en;
  const template = table[key] ?? en[key] ?? key;
  if (!params) {
    return template;
  }
  return template.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = params[name];
    return value === undefined ? match : String(value);
  });
};
