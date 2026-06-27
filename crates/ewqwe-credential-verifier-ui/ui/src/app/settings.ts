/**
 * Settings — app branding, user language, and credential claims selection.
 *
 * Depends on: state (DOM helpers, currentUser), i18n (loadI18n, getSavedLang,
 *             setSavedLang, detectBrowserLang, currentLang),
 *             routing (buildNav)
 */

import { apiFetch } from "../api.ts";
import type { AppSettings } from "../types.ts";
import {
  $,
  toast,
  i18n,
  currentUser,
  applyBranding,
  CLAIM_DEFAULTS,
} from "./state.ts";
import {
  loadI18n,
  getSavedLang,
  setSavedLang,
  detectBrowserLang,
  t,
} from "./i18n.ts";
import { currentLang } from "./state.ts";
import { buildNav } from "./routing.ts";

// ── Load settings ─────────────────────────────────────────────────────────

export async function loadSettings(): Promise<void> {
  try {
    const settings = await apiFetch<AppSettings>("/settings");
    ($("settings-app-name") as HTMLInputElement).value =
      settings.app_name ?? "";
    ($("settings-logo-url") as HTMLInputElement).value =
      settings.logo_url ?? "";
  } catch {
    // ignore
  }

  const langSelect = $("settings-language") as HTMLSelectElement | null;
  if (langSelect) {
    const saved = getSavedLang();
    langSelect.value = saved ?? "default";
  }

  loadClaimsSettings();
}

function loadClaimsSettings(): void {
  const claimGroups = [
    { key: "verifier_ui_pid_claims", selector: ".pid-claim-cb" },
    { key: "verifier_ui_mdl_claims", selector: ".mdl-claim-cb" },
    { key: "verifier_ui_france_claims", selector: ".france-claim-cb" },
  ];

  for (const { key, selector } of claimGroups) {
    try {
      const saved: string[] = JSON.parse(
        localStorage.getItem(key) ?? JSON.stringify(CLAIM_DEFAULTS[key]),
      );
      document.querySelectorAll<HTMLInputElement>(selector).forEach((cb) => {
        cb.checked = saved.includes(cb.value);
      });
    } catch {
      // ignore
    }
  }
}

// ── Save settings ─────────────────────────────────────────────────────────

export async function saveSettings(): Promise<void> {
  const pidChecked = document.querySelectorAll(".pid-claim-cb:checked").length;
  const mdlChecked = document.querySelectorAll(".mdl-claim-cb:checked").length;
  const franceChecked = document.querySelectorAll(
    ".france-claim-cb:checked",
  ).length;
  if (pidChecked === 0 || mdlChecked === 0 || franceChecked === 0) {
    toast(
      i18n["claims_min_one"] ??
        "Select at least one claim per credential type.",
      false,
    );
    return;
  }

  if (currentUser?.role === "admin") {
    try {
      const body = {
        app_name: ($("settings-app-name") as HTMLInputElement).value.trim(),
        logo_url: ($("settings-logo-url") as HTMLInputElement).value.trim(),
      };
      await apiFetch<unknown>("/admin/settings", { method: "PUT", body });
    } catch (err) {
      toast((err as Error).message, false);
      return;
    }
  }

  const langSelect = $("settings-language") as HTMLSelectElement | null;
  if (langSelect) {
    const lang = langSelect.value;
    setSavedLang(lang);
    const effectiveLang = lang === "default" ? detectBrowserLang() : lang;
    if (effectiveLang !== currentLang) {
      await loadI18n(effectiveLang);
      buildNav();
    }
  }

  const pidClaims: string[] = [];
  document
    .querySelectorAll<HTMLInputElement>(".pid-claim-cb:checked")
    .forEach((cb) => pidClaims.push(cb.value));
  localStorage.setItem("verifier_ui_pid_claims", JSON.stringify(pidClaims));

  const mdlClaims: string[] = [];
  document
    .querySelectorAll<HTMLInputElement>(".mdl-claim-cb:checked")
    .forEach((cb) => mdlClaims.push(cb.value));
  localStorage.setItem("verifier_ui_mdl_claims", JSON.stringify(mdlClaims));

  const franceClaims: string[] = [];
  document
    .querySelectorAll<HTMLInputElement>(".france-claim-cb:checked")
    .forEach((cb) => franceClaims.push(cb.value));
  localStorage.setItem(
    "verifier_ui_france_claims",
    JSON.stringify(franceClaims),
  );

  await applyBranding();
  toast(t("settings_saved"), true);
}
