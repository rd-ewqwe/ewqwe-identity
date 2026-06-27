/**
 * Internationalization (i18n) — language detection, loading, and DOM apply.
 *
 * Depends on: state (DOM helpers, i18n/currentLang variables)
 */

import { apiFetch } from "../api.ts";
import {
  $,
  hide,
  show,
  i18n,
  currentLang,
  SUPPORTED_LANGS,
  setI18n,
  setCurrentLang,
} from "./state.ts";

// ── Language detection ────────────────────────────────────────────────────

export function detectBrowserLang(): string {
  const nav =
    navigator.language ||
    (navigator as Navigator & { userLanguage?: string }).userLanguage ||
    "en";
  const short = nav.split("-")[0]!.toLowerCase();
  return SUPPORTED_LANGS.includes(short) ? short : "en";
}

export async function loadI18n(lang: string): Promise<void> {
  try {
    const data = await apiFetch<Record<string, string>>(
      `/i18n?lang=${encodeURIComponent(lang)}`,
    );
    console.log("i18n loaded:", lang, Object.keys(data ?? {}).length, "keys");
    if (data) {
      setI18n(data);
      setCurrentLang(lang);
    }
  } catch (e) {
    console.warn("i18n: failed to load", lang, e);
  }
  applyI18n();
}

export function t(key: string): string {
  return i18n[key] ?? key;
}

export function applyI18n(): void {
  document.querySelectorAll<HTMLElement>("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n")!;
    const val = i18n[key];
    if (val) el.textContent = val;
  });
  const title = $("page-title");
  if (title) title.textContent = i18n["app_name"] ?? "Verifier App";
}

export function getSavedLang(): string | null {
  try {
    return localStorage.getItem("verifier_ui_lang");
  } catch {
    return null;
  }
}

export function setSavedLang(lang: string): void {
  try {
    localStorage.setItem("verifier_ui_lang", lang);
  } catch {
    // ignore
  }
}

export function getEffectiveLang(): string {
  const saved = getSavedLang();
  if (saved && saved !== "default") return saved;
  return detectBrowserLang();
}
