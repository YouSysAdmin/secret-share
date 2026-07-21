// Tiny runes-based i18n: flat dot-keyed dictionaries, {param} interpolation,
// and Intl.PluralRules-backed count phrases. No runtime dependency - locales
// are bundled at build time.
//
// Usage:
//   import { t, tn, i18n, setLocale, localeNames } from "$lib/i18n.svelte.js";
//   {t("create.title")}                      - plain lookup (reactive)
//   {t("create.fileHint", { max: "5 MB" })}  - interpolation
//   {tn("reveal.viewsLeft", n)}              - plural: key_one/_few/_many/_other

import en from "./locales/en.js";
import uk from "./locales/uk.js";

const dictionaries = { en, uk };

export const localeNames = { en: "English", uk: "Українська" };

const STORAGE_KEY = "share_locale";

function detectLocale() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored && dictionaries[stored]) return stored;
  } catch {
    /* storage unavailable */
  }
  if (typeof navigator !== "undefined") {
    for (const lang of navigator.languages || [navigator.language]) {
      const short = (lang || "").slice(0, 2).toLowerCase();
      if (dictionaries[short]) return short;
    }
  }
  return "en";
}

export const i18n = $state({ locale: detectLocale() });

export function setLocale(locale) {
  if (!dictionaries[locale]) return;
  i18n.locale = locale;
  try {
    localStorage.setItem(STORAGE_KEY, locale);
  } catch {
    /* storage unavailable */
  }
}

function interpolate(s, params) {
  if (!params) return s;
  return s.replace(/\{(\w+)\}/g, (m, k) => (k in params ? String(params[k]) : m));
}

// t returns the translation for key in the active locale, falling back to
// English and then to the key itself (a visible marker for a missing string).
export function t(key, params) {
  const dict = dictionaries[i18n.locale] || en;
  const s = dict[key] ?? en[key] ?? key;
  return interpolate(s, params);
}

// tn picks the plural form of key for count n: it tries `${key}_<category>`
// (per Intl.PluralRules: one/few/many/other), then `${key}_other`. The count
// is exposed to the template as {n}.
export function tn(key, n, params) {
  let category = "other";
  try {
    category = new Intl.PluralRules(i18n.locale).select(n);
  } catch {
    /* unknown locale - keep "other" */
  }
  const dict = dictionaries[i18n.locale] || en;
  const s =
    dict[`${key}_${category}`] ??
    dict[`${key}_other`] ??
    en[`${key}_${category}`] ??
    en[`${key}_other`] ??
    key;
  return interpolate(s, { ...params, n });
}
