import React, { createContext, useContext, useState, useCallback, useEffect, useMemo } from "react";
import type { Locale, TranslationKey } from "./types";
import en from "./locales/en.json";
import fa from "./locales/fa.json";
import zh from "./locales/zh.json";
import es from "./locales/es.json";

const localeData: Record<Locale, Record<string, string>> = { en, fa, zh, es };

interface I18nContextValue {
  t: (key: TranslationKey | string, fallback?: string) => string;
  locale: Locale;
  setLocale: (locale: Locale) => void;
  locales: { code: Locale; name: string }[];
}

const I18nContext = createContext<I18nContextValue | null>(null);

function detectBrowserLocale(): Locale {
  try {
    const raw = navigator.language?.split("-")[0] || "";
    if (raw in localeData) return raw as Locale;
  } catch {
    // navigator may not be available (SSR)
  }
  return "en";
}

export function I18nProvider({ children }: { children: React.ReactNode }) {
  // Localization is temporarily locked to English while the switcher is hidden
  // (PROJECT-REVIEW.md rec 2 / B4): browser auto-detect + RTL are deferred until
  // translation coverage and RTL layout land. detectBrowserLocale is retained
  // for when the switcher returns.
  void detectBrowserLocale;
  const [locale, setLocaleState] = useState<Locale>("en");

  useEffect(() => {
    document.documentElement.lang = locale === "fa" ? "fa" : locale === "zh" ? "zh-CN" : locale === "es" ? "es" : "en";
  }, [locale]);

  const setLocale = useCallback((l: Locale) => {
    localStorage.setItem("janus_locale", l);
    setLocaleState(l);
  }, []);

  const t = useCallback(
    (key: TranslationKey | string, fallback?: string): string => {
      const translations = localeData[locale];
      return (translations as Record<string, string>)[key] ?? fallback ?? key;
    },
    [locale]
  );

  const locales = useMemo(
    () => [
      { code: "en" as Locale, name: "English" },
      { code: "fa" as Locale, name: "فارسی" },
      { code: "zh" as Locale, name: "中文 (简体)" },
      { code: "es" as Locale, name: "Español" },
    ],
    []
  );

  return (
    <I18nContext.Provider value={{ t, locale, setLocale, locales }}>
      {children}
    </I18nContext.Provider>
  );
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error("useI18n must be used within an I18nProvider");
  }
  return ctx;
}
