/**
 * Shared global state, DOM helpers, and branding logic.
 * This module has no imports from other app/* modules.
 */

import { apiFetch } from "../api.ts";
import type { AppSettings, User } from "../types.ts";

// ── Global state ──────────────────────────────────────────────────────────

export let currentUser: User | null = null;
export let i18n: Record<string, string> = {};
export let currentLang = "en";
export let currentPage = "home";
export let pollTimer: ReturnType<typeof setInterval> | null = null;
export let currentTransactionId: string | null = null;
export let journalOffset = 0;
export let journalLimit = 10;
export let editingUserId: string | null = null;
export let serverAllowedTypes: string[] = [];
export let qrTypeSelectorWasVisible = false;

export function setCurrentUser(u: User | null): void {
  currentUser = u;
}
export function setI18n(data: Record<string, string>): void {
  i18n = data;
}
export function setCurrentLang(lang: string): void {
  currentLang = lang;
}
export function setCurrentPage(page: string): void {
  currentPage = page;
}
export function setPollTimer(timer: ReturnType<typeof setInterval> | null): void {
  pollTimer = timer;
}
export function setCurrentTransactionId(id: string | null): void {
  currentTransactionId = id;
}
export function setJournalOffset(offset: number): void {
  journalOffset = offset;
}
export function setJournalLimit(limit: number): void {
  journalLimit = limit;
}
export function setEditingUserId(id: string | null): void {
  editingUserId = id;
}
export function setServerAllowedTypes(types: string[]): void {
  serverAllowedTypes = types;
}
export function setQrTypeSelectorWasVisible(v: boolean): void {
  qrTypeSelectorWasVisible = v;
}

export const SUPPORTED_LANGS = ["en", "fr", "de", "it", "es", "sv", "pl", "cs", "hr"];

// ── DOM helpers ───────────────────────────────────────────────────────────

export function $(id: string): HTMLElement | null {
  return document.getElementById(id);
}

export function show(el: string | HTMLElement | null): void {
  if (typeof el === "string") el = $(el);
  if (!el) return;
  el.classList.remove("hidden");
  if (
    el.dataset["display"] === "flex" ||
    el.id === "page-login" ||
    el.id === "page-bootstrap" ||
    el.id === "app-shell" ||
    el.id === "modal-user" ||
    el.id === "mu-active-wrap" ||
    el.id.startsWith("page-") ||
    el.id.startsWith("qr-area-")
  ) {
    el.classList.add("flex");
  }
}

export function hide(el: string | HTMLElement | null): void {
  if (typeof el === "string") el = $(el);
  if (!el) return;
  el.classList.add("hidden");
  el.classList.remove("flex");
}

export function escapeHtml(str: string | null | undefined): string {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

// ── Toast ─────────────────────────────────────────────────────────────────

export function toast(msg: string, ok = true): void {
  const t = $("toast");
  if (!t) return;
  t.textContent = msg;
  t.className = "show " + (ok ? "ok" : "err");
  setTimeout(() => (t.className = ""), 2600);
}

// ── Branding ──────────────────────────────────────────────────────────────

export async function applyBranding(): Promise<void> {
  try {
    const settings = await apiFetch<AppSettings>("/settings");
    const companyName = (settings.app_name ?? "").trim();
    const logoUrl = (settings.logo_url ?? "").trim();

    setServerAllowedTypes(settings.allowed_credential_types ?? []);

    const setLogoAndName = (
      logoEl: HTMLElement | null,
      nameEl: HTMLElement | null,
    ) => {
      if (nameEl) {
        nameEl.textContent = companyName;
        if (companyName) show(nameEl);
        else hide(nameEl);
      }
      if (logoEl && logoEl instanceof HTMLImageElement) {
        if (logoUrl) {
          logoEl.src = logoUrl;
          show(logoEl);
        } else {
          hide(logoEl);
        }
      }
    };

    setLogoAndName($("topbar-logo"), $("topbar-app-name"));
    setLogoAndName($("login-logo"), $("login-company-name"));
    setLogoAndName($("bootstrap-logo"), $("bootstrap-company-name"));

    const drawerName = $("drawer-app-name");
    if (drawerName) drawerName.textContent = companyName;
  } catch {
    // Settings may be unavailable before bootstrap
  }
}
