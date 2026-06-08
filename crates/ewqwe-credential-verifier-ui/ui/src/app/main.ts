/**
 * Main orchestrator — app init, authentication, page routing, and global
 * window assignments for inline HTML `onclick` handlers.
 *
 * Depends on: all app/* modules.
 */

import { apiFetch } from "../api.ts";
import type { SetupStatus, User } from "../types.ts";
import {
  $,
  hide,
  show,
  toast,
  currentUser,
  currentPage,
  setCurrentUser,
  setCurrentPage,
  applyBranding,
} from "./state.ts";
import { loadI18n, getEffectiveLang, t } from "./i18n.ts";
import { buildNav, openDrawer, closeDrawer } from "./routing.ts";
import { setupQRPage, generateQR, cancelQR, resetQR } from "./qrcode.ts";
import {
  loadUsers,
  openCreateUserModal,
  openEditUserModal,
  closeUserModal,
  submitUserModal,
  confirmDeleteUser,
} from "./users.ts";
import {
  loadJournal,
  journalPage,
  clearJournalFilters,
  initJournalPage,
} from "./journal.ts";
import { loadSettings, saveSettings } from "./settings.ts";

// ── Page routing ──────────────────────────────────────────────────────────

export function navigateTo(page: string): void {
  setCurrentPage(page);
  ["page-home", "page-users", "page-journal", "page-settings"].forEach(hide);
  show("page-" + page);

  // Update nav highlight
  document.querySelectorAll<HTMLElement>(".nav-link").forEach((btn) => {
    btn.classList.toggle("active", btn.textContent?.trim() === page);
  });

  if (page === "users") void loadUsers();
  if (page === "journal") initJournalPage();
  if (page === "settings") void loadSettings();
  if (page === "home") setupQRPage();
}

// ── Page transitions ──────────────────────────────────────────────────────

function showLoginPage(): void {
  hide("app-shell");
  hide("page-bootstrap");
  show("page-login");
}

function showBootstrapPage(): void {
  hide("app-shell");
  hide("page-login");
  show("page-bootstrap");
}

function showAppShell(): void {
  hide("page-login");
  hide("page-bootstrap");
  show("app-shell");
  buildNav();
  navigateTo(currentPage || "home");
}

async function onAuthenticated(): Promise<void> {
  await applyBranding();
  showAppShell();
}

// ── Authentication ────────────────────────────────────────────────────────

export async function doLogin(e: Event): Promise<void> {
  e.preventDefault();
  const email = ($("login-email") as HTMLInputElement).value.trim();
  const password = ($("login-password") as HTMLInputElement).value;
  const errEl = $("login-error");

  try {
    if (errEl) hide(errEl);
    const user = await apiFetch<User>("/auth/login", {
      method: "POST",
      body: { email, password },
    });
    setCurrentUser(user);
    await onAuthenticated();
  } catch (err) {
    if (errEl) {
      errEl.textContent = t("invalid_credentials");
      show(errEl);
    }
  }
}

export async function doBootstrap(e: Event): Promise<void> {
  e.preventDefault();
  const pw1 = ($("bs-password") as HTMLInputElement).value;
  const pw2 = ($("bs-password2") as HTMLInputElement).value;
  const errEl = $("bs-error");

  if (pw1 !== pw2) {
    if (errEl) {
      errEl.textContent = t("passwords_dont_match");
      show(errEl);
    }
    return;
  }

  try {
    if (errEl) hide(errEl);
    const user = await apiFetch<User>("/setup/bootstrap", {
      method: "POST",
      body: {
        email: ($("bs-email") as HTMLInputElement).value.trim(),
        password: pw1,
        first_name: ($("bs-first") as HTMLInputElement).value.trim() || null,
        last_name: ($("bs-last") as HTMLInputElement).value.trim() || null,
      },
    });
    toast(t("admin_created"), true);
    setCurrentUser(user);
    await onAuthenticated();
  } catch (err) {
    if (errEl) {
      errEl.textContent = (err as Error).message;
      show(errEl);
    }
  }
}

export async function doLogout(): Promise<void> {
  try {
    await apiFetch<null>("/auth/logout", { method: "POST" });
  } catch {
    // ignore
  }
  setCurrentUser(null);
  setCurrentPage("home");
  cancelQR();
  closeDrawer();
  showLoginPage();
}

// ── App init ──────────────────────────────────────────────────────────────

export async function initApp(): Promise<void> {
  const lang = getEffectiveLang();
  await loadI18n(lang);
  await applyBranding();

  try {
    const status = await apiFetch<SetupStatus>("/setup/status");
    if (!status.bootstrapped) {
      showBootstrapPage();
      return;
    }
  } catch {
    // fall through to login
  }

  try {
    const user = await apiFetch<User>("/auth/me");
    if (user) {
      setCurrentUser(user);
      await onAuthenticated();
      return;
    }
  } catch {
    // not authenticated
  }

  showLoginPage();
}

// ── Expose globals for inline HTML handlers ───────────────────────────────

window.doLogin = doLogin;
window.doBootstrap = doBootstrap;
window.doLogout = doLogout;
window.openDrawer = openDrawer;
window.closeDrawer = closeDrawer;
window.generateQR = generateQR;
window.cancelQR = cancelQR;
window.resetQR = resetQR;
window.openCreateUserModal = openCreateUserModal;
window.openEditUserModal = openEditUserModal;
window.closeUserModal = closeUserModal;
window.submitUserModal = submitUserModal;
window.confirmDeleteUser = confirmDeleteUser;
window.loadJournal = loadJournal;
window.journalPage = journalPage;
window.clearJournalFilters = clearJournalFilters;
window.loadSettings = loadSettings;
window.saveSettings = saveSettings;
window.navigateTo = navigateTo;
