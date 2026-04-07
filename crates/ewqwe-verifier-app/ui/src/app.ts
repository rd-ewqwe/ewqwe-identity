/**
 * Verifier App — main application logic.
 *
 * All API calls go through `apiFetch` which prepends `/api/v1` to the path.
 * Functions that need to be reachable from inline HTML `onclick` handlers are
 * assigned to `window` at the bottom of this file.
 */

import { apiFetch } from "./api.ts";
import type {
  AppSettings,
  JournalEntry,
  QrResponse,
  QrStatus,
  SetupStatus,
  User,
} from "./types.ts";

// ── Global state ──────────────────────────────────────────────────────────

let currentUser: User | null = null;
let i18n: Record<string, string> = {};
let currentLang = "en";
let currentPage = "home";
let pollTimer: ReturnType<typeof setInterval> | null = null;
let currentTransactionId: string | null = null;
let journalOffset = 0;
let journalLimit = 10;
let editingUserId: string | null = null;
let serverAllowedTypes: string[] = [];
let qrTypeSelectorWasVisible = false;

const SUPPORTED_LANGS = ["en", "fr", "de", "it", "es", "sv", "pl", "cs", "hr"];

// ── DOM helpers ───────────────────────────────────────────────────────────

function $(id: string): HTMLElement | null {
  return document.getElementById(id);
}

function show(el: string | HTMLElement | null): void {
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

function hide(el: string | HTMLElement | null): void {
  if (typeof el === "string") el = $(el);
  if (!el) return;
  el.classList.add("hidden");
  el.classList.remove("flex");
}

function escapeHtml(str: string | null | undefined): string {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

// ── Toast ─────────────────────────────────────────────────────────────────

function toast(msg: string, ok = true): void {
  const t = $("toast");
  if (!t) return;
  t.textContent = msg;
  t.className = "show " + (ok ? "ok" : "err");
  setTimeout(() => (t.className = ""), 2600);
}

// ── i18n ──────────────────────────────────────────────────────────────────

function detectBrowserLang(): string {
  const nav =
    navigator.language ||
    (navigator as Navigator & { userLanguage?: string }).userLanguage ||
    "en";
  const short = nav.split("-")[0]!.toLowerCase();
  return SUPPORTED_LANGS.includes(short) ? short : "en";
}

async function loadI18n(lang: string): Promise<void> {
  try {
    const data = await apiFetch<Record<string, string>>(
      `/i18n?lang=${encodeURIComponent(lang)}`,
    );
    if (data) {
      i18n = data;
      currentLang = lang;
    }
  } catch {
    // keep previous translations on failure
  }
  applyI18n();
}

function t(key: string): string {
  return i18n[key] ?? key;
}

function applyI18n(): void {
  document.querySelectorAll<HTMLElement>("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n")!;
    const val = i18n[key];
    if (val) el.textContent = val;
  });
  const title = $("page-title");
  if (title) title.textContent = i18n["app_name"] ?? "Verifier App";
}

function getSavedLang(): string | null {
  try {
    return localStorage.getItem("verifier_app_lang");
  } catch {
    return null;
  }
}

function setSavedLang(lang: string): void {
  try {
    localStorage.setItem("verifier_app_lang", lang);
  } catch {
    // ignore
  }
}

function getEffectiveLang(): string {
  const saved = getSavedLang();
  if (saved && saved !== "default") return saved;
  return detectBrowserLang();
}

// ── Branding ──────────────────────────────────────────────────────────────

async function applyBranding(): Promise<void> {
  try {
    const settings = await apiFetch<AppSettings>("/settings");
    const companyName = (settings.app_name ?? "").trim();
    const logoUrl = (settings.logo_url ?? "").trim();

    serverAllowedTypes = settings.allowed_credential_types ?? [];

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

// ── Navigation ────────────────────────────────────────────────────────────

interface NavItem {
  id: string;
  icon: string;
  label: string;
}

const NAV_ITEMS_ADMIN: NavItem[] = [
  { id: "home", icon: "🏠", label: "home" },
  { id: "users", icon: "👥", label: "users" },
  { id: "journal", icon: "📋", label: "journal" },
  { id: "settings", icon: "⚙️", label: "settings" },
];
const NAV_ITEMS_VERIFIER: NavItem[] = [
  { id: "home", icon: "🏠", label: "home" },
];

function buildNav(): void {
  if (!currentUser) return;
  const items =
    currentUser.role === "admin" ? NAV_ITEMS_ADMIN : NAV_ITEMS_VERIFIER;

  const renderItems = (container: HTMLElement | null) => {
    if (!container) return;
    container.innerHTML = "";
    items.forEach((item) => {
      const btn = document.createElement("button");
      btn.className =
        "nav-link" + (currentPage === item.id ? " active" : "");
      btn.innerHTML = `<span>${item.icon}</span> <span data-i18n="${item.label}">${t(item.label)}</span>`;
      btn.onclick = () => {
        navigateTo(item.id);
        closeDrawer();
      };
      container.appendChild(btn);
    });
    const logoutBtn = document.createElement("button");
    logoutBtn.className = "nav-link text-red-300/70";
    logoutBtn.innerHTML = `<span>🚪</span> <span data-i18n="logout">${t("logout")}</span>`;
    logoutBtn.onclick = doLogout;
    container.appendChild(logoutBtn);
  };

  renderItems($("topbar-nav"));
  renderItems($("drawer-nav"));
}

export function navigateTo(page: string): void {
  currentPage = page;
  ["page-home", "page-users", "page-journal", "page-settings"].forEach(hide);
  show("page-" + page);

  document.querySelectorAll<HTMLElement>(".nav-link").forEach((btn) => {
    const link = btn.querySelector<HTMLElement>("[data-i18n]");
    const key = link?.getAttribute("data-i18n") ?? "";
    const navItem = [...NAV_ITEMS_ADMIN, ...NAV_ITEMS_VERIFIER].find(
      (n) => n.label === key,
    );
    if (navItem) btn.classList.toggle("active", navItem.id === page);
  });

  if (page === "users") void loadUsers();
  if (page === "journal") initJournalPage();
  if (page === "settings") void loadSettings();
  if (page === "home") setupQRPage();
}

// ── Page helpers ──────────────────────────────────────────────────────────

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
  navigateTo(currentPage);
}

// ── Drawer (mobile) ───────────────────────────────────────────────────────

export function openDrawer(): void {
  const drawer = $("drawer");
  const overlay = $("drawer-overlay");
  if (drawer) {
    show(drawer);
    setTimeout(() => drawer.classList.add("open"), 10);
  }
  if (overlay) show(overlay);
}

export function closeDrawer(): void {
  const drawer = $("drawer");
  const overlay = $("drawer-overlay");
  if (drawer) {
    drawer.classList.remove("open");
    setTimeout(() => hide(drawer), 260);
  }
  if (overlay) hide(overlay);
}

// ── Authentication ────────────────────────────────────────────────────────

export async function doLogin(e: Event): Promise<void> {
  e.preventDefault();
  const email = (
    $("login-email") as HTMLInputElement
  ).value.trim();
  const password = (
    $("login-password") as HTMLInputElement
  ).value;
  const errEl = $("login-error");

  try {
    if (errEl) hide(errEl);
    const user = await apiFetch<User>("/auth/login", {
      method: "POST",
      body: { email, password },
    });
    currentUser = user;
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
        first_name:
          ($("bs-first") as HTMLInputElement).value.trim() || null,
        last_name:
          ($("bs-last") as HTMLInputElement).value.trim() || null,
      },
    });
    toast(t("admin_created"), true);
    currentUser = user;
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
  currentUser = null;
  currentPage = "home";
  stopPolling();
  closeDrawer();
  showLoginPage();
}

async function onAuthenticated(): Promise<void> {
  await applyBranding();
  showAppShell();
}

// ── QR Code ───────────────────────────────────────────────────────────────

function setupQRPage(): void {
  if (!currentUser) return;

  const userTypes = currentUser.allowed_credential_types ?? [];
  const allTypes = ["proof-of-age", "mdl", "national-id"];

  let effectiveTypes: string[];
  if (userTypes.length > 0) {
    effectiveTypes = userTypes.filter(
      (t) => serverAllowedTypes.length === 0 || serverAllowedTypes.includes(t),
    );
  } else if (serverAllowedTypes.length > 0) {
    effectiveTypes = serverAllowedTypes;
  } else {
    effectiveTypes = allTypes;
  }

  const typeSelector = $("qr-type-selector");
  const cancelBtn = $("qr-cancel-btn");
  const select = $("qr-credential-type") as HTMLSelectElement;

  if (effectiveTypes.length === 1) {
    hide(typeSelector);
    select.value = effectiveTypes[0]!;
    if (currentUser.role === "verifier") {
      setTimeout(() => void generateQR(), 100);
    }
  } else {
    show(typeSelector);
    select.querySelectorAll<HTMLOptionElement>("option").forEach((opt) => {
      opt.style.display = effectiveTypes.includes(opt.value) ? "" : "none";
    });
    if (!effectiveTypes.includes(select.value)) {
      select.value = effectiveTypes[0]!;
    }
  }

  if (cancelBtn) {
    if (effectiveTypes.length <= 1 && currentUser.role === "verifier") {
      hide(cancelBtn);
    }
  }
}

export async function generateQR(): Promise<void> {
  const select = $("qr-credential-type") as HTMLSelectElement;
  const credType = select.value;

  hideAllQRStates();
  show("qr-area-loading");

  try {
    const data = await apiFetch<QrResponse>("/qr/generate", {
      method: "POST",
      body: { credential_type: credType },
    });

    currentTransactionId = data.transaction_id;

    const typeSelector = $("qr-type-selector");
    qrTypeSelectorWasVisible =
      qrTypeSelectorWasVisible ||
      !!(typeSelector && !typeSelector.classList.contains("hidden"));
    hide("qr-type-selector");

    const selectedOpt = select.options[select.selectedIndex];
    const i18nKey = selectedOpt?.getAttribute("data-i18n");
    const typeLabel =
      i18nKey ? t(i18nKey) : (selectedOpt?.textContent?.trim() ?? "");
    const titleEl = $("qr-title");
    if (titleEl && typeLabel) titleEl.textContent = typeLabel;

    hideAllQRStates();
    show("qr-area-code");
    ($("qr-img") as HTMLImageElement).src = data.qr_code_data_url;
    const badge = $("qr-status-badge");
    if (badge) {
      badge.textContent = t("waiting_for_scan");
      badge.className = "badge badge-indigo px-4 py-1 text-sm";
    }

    const cancelBtn = $("qr-cancel-btn");
    if (cancelBtn && qrTypeSelectorWasVisible) show(cancelBtn);

    startPolling(data.transaction_id);
  } catch (err) {
    hideAllQRStates();
    show("qr-area-empty");
    toast((err as Error).message, false);
  }
}

export function cancelQR(): void {
  stopPolling();
  currentTransactionId = null;
  resetQR();
}

export function resetQR(): void {
  stopPolling();
  currentTransactionId = null;
  hideAllQRStates();
  show("qr-area-empty");
  if (qrTypeSelectorWasVisible) show("qr-type-selector");
  qrTypeSelectorWasVisible = false;
  const titleEl = $("qr-title");
  if (titleEl) titleEl.textContent = t("credential_verification_qr");
}

function hideAllQRStates(): void {
  [
    "qr-area-empty",
    "qr-area-loading",
    "qr-area-code",
    "qr-area-verified",
    "qr-area-failed",
  ].forEach(hide);
}

function startPolling(txId: string): void {
  stopPolling();
  pollTimer = setInterval(() => void pollStatus(txId), 2000);
}

function stopPolling(): void {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

async function pollStatus(txId: string): Promise<void> {
  try {
    const data = await apiFetch<QrStatus>(
      `/qr/${encodeURIComponent(txId)}/status`,
    );
    const status = data.status;

    if (status === "verified" || status === "completed") {
      stopPolling();
      hideAllQRStates();

      const ageEl = $("qr-age-result");
      if (ageEl) {
        if (data.age_over_18 === true) {
          ageEl.textContent = t("age_over_18_true");
          ageEl.className =
            "text-base font-semibold px-4 py-1 rounded-full text-green-900 bg-green-300";
          ageEl.classList.remove("hidden");
        } else if (data.age_over_18 === false) {
          ageEl.textContent = t("age_over_18_false");
          ageEl.className =
            "text-base font-semibold px-4 py-1 rounded-full text-amber-900 bg-amber-300";
          ageEl.classList.remove("hidden");
        } else {
          ageEl.classList.add("hidden");
        }
      }
      show("qr-area-verified");
    } else if (
      status === "failed" ||
      status === "expired" ||
      status === "rejected"
    ) {
      stopPolling();
      hideAllQRStates();
      show("qr-area-failed");
      const reason = $("qr-fail-reason");
      if (reason) {
        reason.textContent =
          status === "expired" ? t("session_expired") : t("presentation_rejected");
      }
    } else if (status === "pending" || status === "scanned") {
      const badge = $("qr-status-badge");
      if (status === "scanned" && badge) {
        badge.textContent = t("wallet_scanning");
        badge.className = "badge badge-amber px-4 py-1 text-sm";
      }
    }
  } catch {
    stopPolling();
    hideAllQRStates();
    show("qr-area-failed");
    const reason = $("qr-fail-reason");
    if (reason) reason.textContent = t("session_expired");
  }
}

// ── Users management ──────────────────────────────────────────────────────

async function loadUsers(): Promise<void> {
  try {
    const users = await apiFetch<User[]>("/admin/users");
    renderUsersTable(users);
  } catch (err) {
    toast((err as Error).message, false);
  }
}

function renderUsersTable(users: User[]): void {
  const tbody = $("users-tbody");
  if (!tbody) return;

  if (!users || users.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center text-white/40 py-6">${t("no_users")}</td></tr>`;
    return;
  }

  tbody.innerHTML = users
    .map((u) => {
      const name =
        [u.first_name, u.last_name].filter(Boolean).join(" ") || "—";
      const roleBadge =
        u.role === "admin"
          ? `<span class="badge badge-indigo">${t("role_admin")}</span>`
          : `<span class="badge badge-green">${t("role_verifier")}</span>`;
      const statusBadge = u.is_active
        ? `<span class="badge badge-green">${t("active")}</span>`
        : `<span class="badge badge-red">${t("inactive")}</span>`;
      const deleteBtn = u.is_superadmin
        ? ""
        : `<button onclick="confirmDeleteUser('${u.id}')" class="btn-danger text-xs px-2 py-1">${t("delete")}</button>`;

      return `<tr>
        <td class="whitespace-nowrap">${escapeHtml(u.email)}</td>
        <td>${escapeHtml(name)}</td>
        <td>${roleBadge}</td>
        <td>${statusBadge}</td>
        <td class="flex gap-2">
          <button onclick="openEditUserModal('${u.id}')" class="btn-ghost text-xs px-2 py-1">${t("edit")}</button>
          ${deleteBtn}
        </td>
      </tr>`;
    })
    .join("");
}

export function openCreateUserModal(): void {
  editingUserId = null;
  const titleEl = $("modal-user-title");
  if (titleEl) titleEl.textContent = t("create_user");
  ($("mu-first") as HTMLInputElement).value = "";
  ($("mu-last") as HTMLInputElement).value = "";
  ($("mu-email") as HTMLInputElement).value = "";
  ($("mu-password") as HTMLInputElement).value = "";
  ($("mu-role") as HTMLSelectElement).value = "verifier";
  ($("mu-active") as HTMLInputElement).checked = true;
  hide("mu-active-wrap");
  ($("mu-password") as HTMLInputElement).required = true;
  hide("mu-error");
  document
    .querySelectorAll<HTMLInputElement>(".mu-cred-cb")
    .forEach((cb) => (cb.checked = false));
  show("modal-user");
}

export async function openEditUserModal(userId: string): Promise<void> {
  editingUserId = userId;
  const titleEl = $("modal-user-title");
  if (titleEl) titleEl.textContent = t("edit_user");
  hide("mu-error");

  try {
    const users = await apiFetch<User[]>("/admin/users");
    const user = users.find((u) => u.id === userId);
    if (!user) {
      toast(t("no_users"), false);
      return;
    }

    ($("mu-first") as HTMLInputElement).value = user.first_name ?? "";
    ($("mu-last") as HTMLInputElement).value = user.last_name ?? "";
    ($("mu-email") as HTMLInputElement).value = user.email;
    ($("mu-password") as HTMLInputElement).value = "";
    ($("mu-password") as HTMLInputElement).required = false;
    ($("mu-role") as HTMLSelectElement).value = user.role;
    ($("mu-active") as HTMLInputElement).checked = user.is_active;
    show("mu-active-wrap");

    document
      .querySelectorAll<HTMLInputElement>(".mu-cred-cb")
      .forEach((cb) => {
        cb.checked = user.allowed_credential_types.includes(cb.value);
      });

    show("modal-user");
  } catch (err) {
    toast((err as Error).message, false);
  }
}

export function closeUserModal(): void {
  hide("modal-user");
  editingUserId = null;
}

export async function submitUserModal(e: Event): Promise<void> {
  e.preventDefault();
  const errEl = $("mu-error");

  const allowedTypes: string[] = [];
  document
    .querySelectorAll<HTMLInputElement>(".mu-cred-cb:checked")
    .forEach((cb) => allowedTypes.push(cb.value));

  if (editingUserId) {
    const body: Record<string, unknown> = {
      first_name:
        ($("mu-first") as HTMLInputElement).value.trim() || null,
      last_name:
        ($("mu-last") as HTMLInputElement).value.trim() || null,
      role: ($("mu-role") as HTMLSelectElement).value,
      is_active: ($("mu-active") as HTMLInputElement).checked,
      allowed_credential_types: allowedTypes,
    };
    const pwd = ($("mu-password") as HTMLInputElement).value;
    if (pwd) body["new_password"] = pwd;

    try {
      if (errEl) hide(errEl);
      await apiFetch<User>(
        `/admin/users/${encodeURIComponent(editingUserId)}`,
        { method: "PUT", body },
      );
      toast(t("user_updated"), true);
      closeUserModal();
      await loadUsers();
    } catch (err) {
      if (errEl) {
        errEl.textContent = (err as Error).message;
        show(errEl);
      }
    }
  } else {
    const body = {
      email: ($("mu-email") as HTMLInputElement).value.trim(),
      password: ($("mu-password") as HTMLInputElement).value,
      first_name:
        ($("mu-first") as HTMLInputElement).value.trim() || null,
      last_name:
        ($("mu-last") as HTMLInputElement).value.trim() || null,
      role: ($("mu-role") as HTMLSelectElement).value,
      allowed_credential_types: allowedTypes,
    };

    try {
      if (errEl) hide(errEl);
      await apiFetch<User>("/admin/users", { method: "POST", body });
      toast(t("user_created"), true);
      closeUserModal();
      await loadUsers();
    } catch (err) {
      if (errEl) {
        errEl.textContent = (err as Error).message;
        show(errEl);
      }
    }
  }
}

export function confirmDeleteUser(userId: string): void {
  if (!confirm(t("delete_user_confirm"))) return;
  void deleteUser(userId);
}

async function deleteUser(userId: string): Promise<void> {
  try {
    await apiFetch<null>(
      `/admin/users/${encodeURIComponent(userId)}`,
      { method: "DELETE" },
    );
    toast(t("user_deleted"), true);
    await loadUsers();
  } catch (err) {
    toast((err as Error).message, false);
  }
}

// ── Journal ───────────────────────────────────────────────────────────────

function initJournalPage(): void {
  setJournalDefaultDates();
  void loadJournalUserFilter();
  void loadJournal(0);
}

function setJournalDefaultDates(): void {
  const fromEl = $("journal-filter-from") as HTMLInputElement | null;
  const toEl = $("journal-filter-to") as HTMLInputElement | null;
  if (fromEl) fromEl.value = "2025-01-01";
  if (toEl) toEl.value = new Date().toISOString().slice(0, 10);
}

async function loadJournalUserFilter(): Promise<void> {
  const select = $("journal-filter-user") as HTMLSelectElement | null;
  if (!select) return;
  const current = select.value;
  while (select.options.length > 1) select.remove(1);
  try {
    const users = await apiFetch<User[]>("/admin/users");
    (users ?? []).forEach((u) => {
      const opt = document.createElement("option");
      opt.value = u.email;
      opt.textContent = u.email;
      select.appendChild(opt);
    });
    if (current) select.value = current;
  } catch {
    // ignore
  }
}

export async function loadJournal(offset: number): Promise<void> {
  journalOffset = offset ?? 0;
  const limitEl = $("journal-limit-select") as HTMLSelectElement | null;
  if (limitEl) journalLimit = parseInt(limitEl.value) || journalLimit;

  const userId =
    ($("journal-filter-user") as HTMLSelectElement | null)?.value ?? "";
  const dateFrom =
    ($("journal-filter-from") as HTMLInputElement | null)?.value ?? "";
  const dateTo =
    ($("journal-filter-to") as HTMLInputElement | null)?.value ?? "";

  let qs = `?limit=${journalLimit}&offset=${journalOffset}`;
  if (userId) qs += "&user_id=" + encodeURIComponent(userId);
  if (dateFrom)
    qs += "&date_from=" + encodeURIComponent(dateFrom + "T00:00:00Z");
  if (dateTo) qs += "&date_to=" + encodeURIComponent(dateTo + "T23:59:59Z");

  try {
    const entries = await apiFetch<JournalEntry[]>("/admin/journal" + qs);
    renderJournal(entries);
  } catch {
    const tbody = $("journal-tbody");
    if (tbody)
      tbody.innerHTML = `<tr><td colspan="4" class="text-center text-white/40 py-6">${t("no_journal")}</td></tr>`;
  }
}

function renderClaims(claims: Record<string, unknown>): string {
  const entries = Object.entries(claims);
  if (entries.length === 0) return '<span class="text-white/40">—</span>';
  return entries
    .map(([k, v]) => {
      if (typeof v === "boolean") {
        const icon = v ? "✓" : "✗";
        const cls = v ? "text-green-400" : "text-red-400";
        return `<span class="${cls} text-xs" title="${escapeHtml(k)}">${icon}&thinsp;${escapeHtml(k)}</span>`;
      }
      return `<span class="text-white/60 text-xs">${escapeHtml(k)}: ${escapeHtml(String(v))}</span>`;
    })
    .join('<span class="text-white/25 mx-1">·</span>');
}

function renderJournal(entries: JournalEntry[]): void {
  const tbody = $("journal-tbody");
  if (!tbody) return;

  const prevBtn = $("journal-prev") as HTMLButtonElement | null;
  const nextBtn = $("journal-next") as HTMLButtonElement | null;

  if (!entries || entries.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-center text-white/40 py-6">${t("no_journal")}</td></tr>`;
    if (prevBtn) prevBtn.disabled = journalOffset === 0;
    if (nextBtn) nextBtn.disabled = true;
    updateJournalPageInfo();
    return;
  }

  tbody.innerHTML = entries
    .map((e) => {
      const time = new Date(e.created_at).toLocaleString();
      const verifier = escapeHtml(e.qrcode_app_user_email ?? "—");
      const claimsHtml = renderClaims(e.claims ?? {});
      const statusBadge = e.success
        ? `<span class="text-green-400 font-semibold">✓</span>`
        : `<span class="text-red-400 font-semibold">✗</span>`;
      return `<tr>
        <td class="whitespace-nowrap">${time}</td>
        <td class="max-w-[220px] truncate" title="${escapeHtml(e.qrcode_app_user_email)}">${verifier}</td>
        <td class="max-w-[260px]">${claimsHtml}</td>
        <td class="text-center">${statusBadge}</td>
      </tr>`;
    })
    .join("");

  if (prevBtn) prevBtn.disabled = journalOffset === 0;
  if (nextBtn) nextBtn.disabled = entries.length < journalLimit;
  updateJournalPageInfo();
}

function updateJournalPageInfo(): void {
  const el = $("journal-page-info");
  if (el) {
    const page = Math.floor(journalOffset / journalLimit) + 1;
    el.textContent = `${t("page")} ${page}`;
  }
}

export function journalPage(dir: number): void {
  const newOffset = journalOffset + dir * journalLimit;
  if (newOffset < 0) return;
  void loadJournal(newOffset);
}

export function clearJournalFilters(): void {
  const filterUser = $("journal-filter-user") as HTMLSelectElement | null;
  const limitEl = $("journal-limit-select") as HTMLSelectElement | null;
  if (filterUser) filterUser.value = "";
  if (limitEl) {
    limitEl.value = "10";
    journalLimit = 10;
  }
  setJournalDefaultDates();
  void loadJournal(0);
}

// ── Settings ──────────────────────────────────────────────────────────────

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
  try {
    const pidClaims: string[] = JSON.parse(
      localStorage.getItem("verifier_app_pid_claims") ??
        JSON.stringify(["age_over_18", "portrait"]),
    );
    document
      .querySelectorAll<HTMLInputElement>(".pid-claim-cb")
      .forEach((cb) => {
        cb.checked = pidClaims.includes(cb.value);
      });
  } catch {
    // ignore
  }

  try {
    const mdlClaims: string[] = JSON.parse(
      localStorage.getItem("verifier_app_mdl_claims") ??
        JSON.stringify(["age_over_18", "portrait"]),
    );
    document
      .querySelectorAll<HTMLInputElement>(".mdl-claim-cb")
      .forEach((cb) => {
        cb.checked = mdlClaims.includes(cb.value);
      });
  } catch {
    // ignore
  }
}

export async function saveSettings(): Promise<void> {
  const pidChecked = document.querySelectorAll(".pid-claim-cb:checked").length;
  const mdlChecked = document.querySelectorAll(".mdl-claim-cb:checked").length;
  if (pidChecked === 0 || mdlChecked === 0) {
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
        app_name:
          ($("settings-app-name") as HTMLInputElement).value.trim(),
        logo_url:
          ($("settings-logo-url") as HTMLInputElement).value.trim(),
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
    const effectiveLang =
      lang === "default" ? detectBrowserLang() : lang;
    if (effectiveLang !== currentLang) {
      await loadI18n(effectiveLang);
      buildNav();
    }
  }

  const pidClaims: string[] = [];
  document
    .querySelectorAll<HTMLInputElement>(".pid-claim-cb:checked")
    .forEach((cb) => pidClaims.push(cb.value));
  localStorage.setItem("verifier_app_pid_claims", JSON.stringify(pidClaims));

  const mdlClaims: string[] = [];
  document
    .querySelectorAll<HTMLInputElement>(".mdl-claim-cb:checked")
    .forEach((cb) => mdlClaims.push(cb.value));
  localStorage.setItem("verifier_app_mdl_claims", JSON.stringify(mdlClaims));

  await applyBranding();
  toast(t("settings_saved"), true);
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
      currentUser = user;
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
