import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import english from "./locales/en.json";
export type Locale = "zh-CN" | "en";
const dictionary: Record<string, string> = english;
const reverse = new Map(
  Object.entries(dictionary).map(([key, value]) => [value, key]),
);
function initialLocale(): Locale {
  try {
    const saved = localStorage.getItem("pero.lang");
    if (saved) return saved.startsWith("en") ? "en" : "zh-CN";
  } catch {}
  return navigator.language.startsWith("zh") ? "zh-CN" : "en";
}
let current: Locale = initialLocale();
/** Source-language message keys keep all product text in one searchable catalogue. */
export function t(
  value: string | undefined,
  params: Record<string, unknown> = {},
): string {
  if (!value) return "";
  const key = dictionary[value] ? value : reverse.get(value) || value;
  const text = current === "en" ? dictionary[key] || value : key;
  return text.replace(/\{\{(\w+)\}\}/g, (_, key) => String(params[key] ?? ""));
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
  }, [locale]);
  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key === "pero.lang") {
        const next: Locale = event.newValue
          ? event.newValue.startsWith("en")
            ? "en"
            : "zh-CN"
          : navigator.language.startsWith("zh")
            ? "zh-CN"
            : "en";
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
