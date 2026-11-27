import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import english from "./locales/en.json";
export type Locale = "zh-CN" | "en";
export type Message = string | (() => string);
const dictionary: Record<string, string> = english;
function preferredLocale(value?: string | null): Locale | undefined {
  if (/^zh(?:-|$)/i.test(value ?? "")) return "zh-CN";
  if (/^en(?:-|$)/i.test(value ?? "")) return "en";
}
function browserLocale(): Locale {
  for (const language of navigator.languages) {
    const locale = preferredLocale(language);
    if (locale) return locale;
  }
  return preferredLocale(navigator.language) ?? "en";
}
function initialLocale(): Locale {
  try {
    const saved = preferredLocale(localStorage.getItem("pero.lang"));
    if (saved) return saved;
  } catch {}
  return browserLocale();
}
let current: Locale = initialLocale();
/** Source-language message keys keep all product text in one searchable catalogue. */
export function t(
  value: Message | undefined,
  params?: Record<string, unknown>,
): string {
  if (!value) return "";
  if (typeof value === "function") return value();
  const text =
    current === "en" && Object.hasOwn(dictionary, value)
      ? dictionary[value]
      : value;
  return params
    ? text.replace(/\{\{(\w+)\}\}/g, (_, key) => String(params[key] ?? ""))
    : text;
}

export function labelValue(label: string, value: string | number) {
  return t("{{label}}：{{value}}", { label: t(label), value });
}
const LocaleContext = createContext<{
  locale: Locale;
  setLocale: (locale: Locale) => void;
}>({ locale: current, setLocale: () => {} });
export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, update] = useState<Locale>(current);
  function setLocale(next: Locale) {
    current = next;
    update(next);
    try {
      localStorage.setItem("pero.lang", next);
    } catch {}
  }
  useEffect(() => {
    document.documentElement.lang = locale;
    // Document redirects (such as social sign-in callbacks) use browser headers.
    // Keep the selected language available for notifications initiated there.
    try {
      const secure = window.location.protocol === "https:" ? "; Secure" : "";
      document.cookie = `pero_lang=${locale}; Path=/; Max-Age=31536000; SameSite=Lax${secure}`;
    } catch {}
  }, [locale]);
  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key === "pero.lang") {
        const next = preferredLocale(event.newValue) ?? browserLocale();
        current = next;
        update(next);
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);
  return (
    <LocaleContext.Provider value={{ locale, setLocale }}>
      {children}
    </LocaleContext.Provider>
  );
}
export const getLocale = () => current;
export const useLocale = () => useContext(LocaleContext);
