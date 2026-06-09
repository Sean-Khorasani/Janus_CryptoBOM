/**
 * useTranslation hook
 *
 * Provides a convenience wrapper around the i18n context.
 * Returns { t, locale, setLocale } where:
 *   - t(key, fallback?) translates a TranslationKey
 *   - locale is the current locale code
 *   - setLocale switches the locale
 */
export { useI18n as useTranslation } from "../i18n";
