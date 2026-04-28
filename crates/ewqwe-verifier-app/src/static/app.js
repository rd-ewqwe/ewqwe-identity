// ═══════════════════════════════════════════════════════════════════════════
// Verifier App — JavaScript Application
// ═══════════════════════════════════════════════════════════════════════════

"use strict";

// ── Global state ──────────────────────────────────────────────────────────
let currentUser = null;
let i18n = {};
let currentLang = "en";
let currentPage = "home";
let pollTimer = null;
let currentTransactionId = null;
let journalOffset = 0;
let journalLimit = 10;
let editingUserId = null;
let defaultLogoDataUrl = null; // loaded lazily from /verifier_app/favicon_b64.txt
let _qrTypeSelectorWasVisible = false;

// Languages supported
const SUPPORTED_LANGS = ["en", "fr", "de", "it", "es", "sv", "pl", "cs", "hr"];

// ── Helpers ───────────────────────────────────────────────────────────────

function $(id) {
  return document.getElementById(id);
}

function show(el) {
  if (typeof el === "string") el = $(el);
  if (!el) return;
  el.classList.remove("hidden");
  // Restore flex if the element originally needs it
  if (
    el.dataset.display === "flex" ||
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

function hide(el) {
  if (typeof el === "string") el = $(el);
  if (!el) return;
  el.classList.add("hidden");
  el.classList.remove("flex");
}

function toast(msg, ok) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "show " + (ok ? "ok" : "err");
  setTimeout(() => (t.className = ""), 2600);
}

async function api(path, opts = {}) {
  const url = "/verifier_app" + path;
  const headers = opts.headers || {};
  if (opts.body && typeof opts.body === "object") {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(url, { ...opts, headers, credentials: "same-origin" });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const msg = data?.error || res.statusText;
    throw new Error(msg);
  }
  return data;
}

// ── i18n ──────────────────────────────────────────────────────────────────

function detectBrowserLang() {
  const nav = navigator.language || navigator.userLanguage || "en";
  const short = nav.split("-")[0].toLowerCase();
  return SUPPORTED_LANGS.includes(short) ? short : "en";
}

async function loadI18n(lang) {
  try {
    const res = await fetch("/verifier_app/api/i18n?lang=" + encodeURIComponent(lang));
    if (res.ok) {
      i18n = await res.json();
      currentLang = lang;
    }
  } catch (_) {
    // fallback: keep previous
  }
  applyI18n();
}

function t(key) {
  return i18n[key] || key;
}

function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    const val = i18n[key];
    if (val) el.textContent = val;
  });
  // Update page title
  const title = $("page-title");
  if (title) title.textContent = i18n["app_name"] || "Verifier App";
}

// ── Language persistence ──────────────────────────────────────────────────

function getSavedLang() {
  try {
    return localStorage.getItem("verifier_app_lang");
  } catch (_) {
    return null;
  }
}

function setSavedLang(lang) {
  try {
    localStorage.setItem("verifier_app_lang", lang);
  } catch (_) {}
}

function getEffectiveLang() {
  const saved = getSavedLang();
  if (saved && saved !== "default") return saved;
  return detectBrowserLang();
}

// ── Default logo ──────────────────────────────────────────────────────────

async function loadDefaultLogo() {
  if (defaultLogoDataUrl) return defaultLogoDataUrl;
  try {
    const res = await fetch("/verifier_app/favicon_b64.txt");
    if (res.ok) {
      defaultLogoDataUrl = (await res.text()).trim();
      return defaultLogoDataUrl;
    }
  } catch (_) {}
  return null;
}

// ── Branding ──────────────────────────────────────────────────────────────

async function applyBranding() {
  try {
    const settings = await api("/api/settings");
    const companyName = (settings.app_name || "").trim();
    const logoUrl = (settings.logo_url || "").trim();

    // Top bar
    const topbarName = $("topbar-app-name");
    if (topbarName) {
      topbarName.textContent = companyName;
      if (companyName) show(topbarName); else hide(topbarName);
    }

    const topbarLogo = $("topbar-logo");
    if (topbarLogo) {
      if (logoUrl) { topbarLogo.src = logoUrl; show(topbarLogo); }
      else hide(topbarLogo);
    }

    // Login branding
    const loginName = $("login-company-name");
    if (loginName) {
      loginName.textContent = companyName;
      if (companyName) show(loginName); else hide(loginName);
    }
    const loginLogo = $("login-logo");
    if (loginLogo) {
      if (logoUrl) { loginLogo.src = logoUrl; show(loginLogo); }
      else hide(loginLogo);
    }

    // Bootstrap branding
    const bsName = $("bootstrap-company-name");
    if (bsName) {
      bsName.textContent = companyName;
      if (companyName) show(bsName); else hide(bsName);
    }
    const bsLogo = $("bootstrap-logo");
    if (bsLogo) {
      if (logoUrl) { bsLogo.src = logoUrl; show(bsLogo); }
      else hide(bsLogo);
    }

    // Drawer name
    const drawerName = $("drawer-app-name");
    if (drawerName) drawerName.textContent = companyName;

    // Store config.allowed_credential_types for QR logic
    if (settings.allowed_credential_types) {
      window._serverAllowedTypes = settings.allowed_credential_types;
    }
  } catch (_) {
    // Settings API may fail before bootstrap
  }
}

// ── Navigation ────────────────────────────────────────────────────────────

const NAV_ITEMS_ADMIN = [
  { id: "home", icon: "🏠", label: "home" },
  { id: "users", icon: "👥", label: "users" },
  { id: "journal", icon: "📋", label: "journal" },
  { id: "settings", icon: "⚙️", label: "settings" },
];
const NAV_ITEMS_VERIFIER = [{ id: "home", icon: "🏠", label: "home" }];

function buildNav() {
  if (!currentUser) return;
  const items =
    currentUser.role === "admin" ? NAV_ITEMS_ADMIN : NAV_ITEMS_VERIFIER;

  function renderItems(container) {
    container.innerHTML = "";
    items.forEach((item) => {
      const btn = document.createElement("button");
      btn.className = "nav-link" + (currentPage === item.id ? " active" : "");
      btn.innerHTML = `<span>${item.icon}</span> <span data-i18n="${item.label}">${t(item.label)}</span>`;
      btn.onclick = () => {
        navigateTo(item.id);
        closeDrawer();
      };
      container.appendChild(btn);
    });
    // Logout button
    const logoutBtn = document.createElement("button");
    logoutBtn.className = "nav-link text-red-300/70";
    logoutBtn.innerHTML = `<span>🚪</span> <span data-i18n="logout">${t("logout")}</span>`;
    logoutBtn.onclick = doLogout;
    container.appendChild(logoutBtn);
  }

  const topbarNav = $("topbar-nav");
  const drawerNav = $("drawer-nav");
  if (topbarNav) renderItems(topbarNav);
  if (drawerNav) renderItems(drawerNav);
}

function navigateTo(page) {
  currentPage = page;
  // Hide all page sections
  ["page-home", "page-users", "page-journal", "page-settings"].forEach((id) =>
    hide(id)
  );
  // Show requested
  show("page-" + page);

  // Update nav active states
  document.querySelectorAll(".nav-link").forEach((btn) => {
    const links = btn.querySelectorAll("[data-i18n]");
    const key = links.length ? links[0].getAttribute("data-i18n") : "";
    const navItem = [...NAV_ITEMS_ADMIN, ...NAV_ITEMS_VERIFIER].find(
      (n) => n.label === key
    );
    if (navItem) {
      btn.classList.toggle("active", navItem.id === page);
    }
  });

  // Load data for page
  if (page === "users") loadUsers();
  if (page === "journal") initJournalPage();
  if (page === "settings") loadSettings();
  if (page === "home") setupQRPage();
}

// ── Pages ─────────────────────────────────────────────────────────────────

function showLoginPage() {
  hide("app-shell");
  hide("page-bootstrap");
  show("page-login");
}

function showBootstrapPage() {
  hide("app-shell");
  hide("page-login");
  show("page-bootstrap");
}

function showAppShell() {
  hide("page-login");
  hide("page-bootstrap");
  show("app-shell");
  buildNav();
  navigateTo(currentPage);
}

// ── Drawer (mobile) ──────────────────────────────────────────────────────

function openDrawer() {
  const drawer = $("drawer");
  const overlay = $("drawer-overlay");
  if (drawer) {
    show(drawer);
    setTimeout(() => drawer.classList.add("open"), 10);
  }
  if (overlay) show(overlay);
}

function closeDrawer() {
  const drawer = $("drawer");
  const overlay = $("drawer-overlay");
  if (drawer) {
    drawer.classList.remove("open");
    setTimeout(() => hide(drawer), 260);
  }
  if (overlay) hide(overlay);
}

// ── Authentication ────────────────────────────────────────────────────────

async function doLogin(e) {
  e.preventDefault();
  const email = $("login-email").value.trim();
  const password = $("login-password").value;
  const errEl = $("login-error");

  try {
    hide(errEl);
    const user = await api("/api/auth/login", {
      method: "POST",
      body: { email, password },
    });
    currentUser = user;
    await onAuthenticated();
  } catch (err) {
    errEl.textContent = t("invalid_credentials");
    show(errEl);
  }
}

async function doBootstrap(e) {
  e.preventDefault();
  const pw1 = $("bs-password").value;
  const pw2 = $("bs-password2").value;
  const errEl = $("bs-error");

  if (pw1 !== pw2) {
    errEl.textContent = t("passwords_dont_match");
    show(errEl);
    return;
  }

  try {
    hide(errEl);
    const user = await api("/api/setup/bootstrap", {
      method: "POST",
      body: {
        email: $("bs-email").value.trim(),
        password: pw1,
        first_name: $("bs-first").value.trim() || null,
        last_name: $("bs-last").value.trim() || null,
      },
    });
    toast(t("admin_created"), true);
    currentUser = user;
    await onAuthenticated();
  } catch (err) {
    errEl.textContent = err.message;
    show(errEl);
  }
}

async function doLogout() {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch (_) {}
  currentUser = null;
  currentPage = "home";
  stopPolling();
  closeDrawer();
  showLoginPage();
}

async function onAuthenticated() {
  await applyBranding();
  showAppShell();
}

// ── QR Code ───────────────────────────────────────────────────────────────

function setupQRPage() {
  if (!currentUser) return;

  // Determine allowed types for this user
  const serverTypes = window._serverAllowedTypes || [];
  const userTypes = currentUser.allowed_credential_types || [];

  // Build effective types list
  let effectiveTypes;
  const allTypes = ["proof-of-age", "mdl", "national-id"];

  if (userTypes.length > 0) {
    effectiveTypes = userTypes.filter(
      (t) => serverTypes.length === 0 || serverTypes.includes(t)
    );
  } else if (serverTypes.length > 0) {
    effectiveTypes = serverTypes;
  } else {
    effectiveTypes = allTypes;
  }

  const typeSelector = $("qr-type-selector");
  const cancelBtn = $("qr-cancel-btn");
  const select = $("qr-credential-type");

  if (effectiveTypes.length === 1) {
    // Single type: hide selector, auto-select
    hide(typeSelector);
    select.value = effectiveTypes[0];

    // For single-type verifiers: auto-generate QR
    if (currentUser.role === "verifier") {
      setTimeout(() => generateQR(), 100);
    }
  } else {
    // Multiple types: show selector
    show(typeSelector);

    // Filter dropdown options
    const options = select.querySelectorAll("option");
    options.forEach((opt) => {
      if (effectiveTypes.includes(opt.value)) {
        opt.style.display = "";
      } else {
        opt.style.display = "none";
      }
    });

    // Ensure selected value is valid
    if (!effectiveTypes.includes(select.value)) {
      select.value = effectiveTypes[0];
    }
  }

  // Cancel button visibility: show when QR is active, but hide for single-type verifiers
  if (cancelBtn) {
    if (effectiveTypes.length <= 1 && currentUser.role === "verifier") {
      hide(cancelBtn);
    }
  }
}

async function generateQR() {
  const credType = $("qr-credential-type").value;

  // Show loading
  hideAllQRStates();
  show("qr-area-loading");

  try {
    const data = await api("/api/qr/generate", {
      method: "POST",
      body: { credential_type: credType },
    });

    currentTransactionId = data.transaction_id;

    // Hide type selector and update title with selected credential type
    const typeSelector = $('qr-type-selector');
    // Preserve true: on re-calls ("New QR Code") the selector is already hidden,
    // so we must not overwrite a previously recorded true value.
    _qrTypeSelectorWasVisible = _qrTypeSelectorWasVisible ||
      !!(typeSelector && !typeSelector.classList.contains('hidden'));
    hide('qr-type-selector');
    const select = $('qr-credential-type');
    const selectedOpt = select && select.options[select.selectedIndex];
    const i18nKey = selectedOpt && selectedOpt.getAttribute('data-i18n');
    const typeLabel = i18nKey ? t(i18nKey) : (selectedOpt && selectedOpt.textContent.trim());
    const titleEl = $('qr-title');
    if (titleEl && typeLabel) titleEl.textContent = typeLabel;

    // Show QR image
    hideAllQRStates();
    show("qr-area-code");
    $("qr-img").src = data.qr_code_data_url;
    $("qr-status-badge").textContent = t("waiting_for_scan");
    $("qr-status-badge").className = "badge badge-indigo px-4 py-1 text-sm";

    // Show cancel button only in multi-type mode (single-type verifiers never need it)
    const cancelBtn = $("qr-cancel-btn");
    if (cancelBtn && _qrTypeSelectorWasVisible) {
      show(cancelBtn);
    }

    // Start polling
    startPolling(data.transaction_id);
  } catch (err) {
    hideAllQRStates();
    show("qr-area-empty");
    toast(err.message, false);
  }
}

function cancelQR() {
  stopPolling();
  currentTransactionId = null;
  resetQR();
}

function resetQR() {
  stopPolling();
  currentTransactionId = null;
  hideAllQRStates();
  show("qr-area-empty");
  // Restore type selector and title
  if (_qrTypeSelectorWasVisible) show("qr-type-selector");
  _qrTypeSelectorWasVisible = false;
  const titleEl = $("qr-title");
  if (titleEl) titleEl.textContent = t("credential_verification_qr");
}

function hideAllQRStates() {
  [
    "qr-area-empty",
    "qr-area-loading",
    "qr-area-code",
    "qr-area-verified",
    "qr-area-failed",
  ].forEach(hide);
}

function startPolling(txId) {
  stopPolling();
  pollTimer = setInterval(() => pollStatus(txId), 2000);
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

async function pollStatus(txId) {
  try {
    const data = await api("/api/qr/" + encodeURIComponent(txId) + "/status");
    const status = data.status;

    if (status === "verified" || status === "completed") {
      stopPolling();
      hideAllQRStates();
      // Show age_over_18 claim result if the backend returned it
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
      if (status === "expired") {
        $("qr-fail-reason").textContent = t("session_expired");
      } else {
        $("qr-fail-reason").textContent = t("presentation_rejected");
      }
    } else if (status === "pending" || status === "scanned") {
      // Update badge
      const badge = $("qr-status-badge");
      if (status === "scanned") {
        badge.textContent = t("wallet_scanning");
        badge.className = "badge badge-amber px-4 py-1 text-sm";
      }
    }
  } catch (_) {
    // Polling error — transaction may have expired
    stopPolling();
    hideAllQRStates();
    show("qr-area-failed");
    $("qr-fail-reason").textContent = t("session_expired");
  }
}

// ── Users management ──────────────────────────────────────────────────────

async function loadUsers() {
  try {
    const users = await api("/api/admin/users");
    renderUsersTable(users);
  } catch (err) {
    toast(err.message, false);
  }
}

function renderUsersTable(users) {
  const tbody = $("users-tbody");
  if (!users || users.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center text-white/40 py-6">${t("no_users")}</td></tr>`;
    return;
  }

  tbody.innerHTML = users
    .map((u) => {
      const name = [u.first_name, u.last_name].filter(Boolean).join(" ") || "—";
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

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str || "";
  return div.innerHTML;
}

// ── User modal ────────────────────────────────────────────────────────────

function openCreateUserModal() {
  editingUserId = null;
  $("modal-user-title").textContent = t("create_user");
  $("mu-first").value = "";
  $("mu-last").value = "";
  $("mu-email").value = "";
  $("mu-password").value = "";
  $("mu-role").value = "verifier";
  $("mu-active").checked = true;
  hide("mu-active-wrap");
  $("mu-password").required = true;
  hide("mu-error");

  // Reset credential type checkboxes
  document.querySelectorAll(".mu-cred-cb").forEach((cb) => (cb.checked = false));

  show("modal-user");
}

async function openEditUserModal(userId) {
  editingUserId = userId;
  $("modal-user-title").textContent = t("edit_user");
  hide("mu-error");

  try {
    const users = await api("/api/admin/users");
    const user = users.find((u) => u.id === userId);
    if (!user) return toast(t("no_users"), false);

    $("mu-first").value = user.first_name || "";
    $("mu-last").value = user.last_name || "";
    $("mu-email").value = user.email;
    $("mu-password").value = "";
    $("mu-password").required = false;
    $("mu-role").value = user.role;
    $("mu-active").checked = user.is_active;
    show("mu-active-wrap");

    // Credential type checkboxes
    document.querySelectorAll(".mu-cred-cb").forEach((cb) => {
      cb.checked = user.allowed_credential_types.includes(cb.value);
    });

    show("modal-user");
  } catch (err) {
    toast(err.message, false);
  }
}

function closeUserModal() {
  hide("modal-user");
  editingUserId = null;
}

async function submitUserModal(e) {
  e.preventDefault();
  const errEl = $("mu-error");

  const allowedTypes = [];
  document.querySelectorAll(".mu-cred-cb:checked").forEach((cb) => {
    allowedTypes.push(cb.value);
  });

  if (editingUserId) {
    // Update
    const body = {
      first_name: $("mu-first").value.trim() || null,
      last_name: $("mu-last").value.trim() || null,
      role: $("mu-role").value,
      is_active: $("mu-active").checked,
      allowed_credential_types: allowedTypes,
    };
    const pwd = $("mu-password").value;
    if (pwd) body.new_password = pwd;

    try {
      hide(errEl);
      await api("/api/admin/users/" + encodeURIComponent(editingUserId), {
        method: "PUT",
        body,
      });
      toast(t("user_updated"), true);
      closeUserModal();
      loadUsers();
    } catch (err) {
      errEl.textContent = err.message;
      show(errEl);
    }
  } else {
    // Create
    const body = {
      email: $("mu-email").value.trim(),
      password: $("mu-password").value,
      first_name: $("mu-first").value.trim() || null,
      last_name: $("mu-last").value.trim() || null,
      role: $("mu-role").value,
      allowed_credential_types: allowedTypes,
    };

    try {
      hide(errEl);
      await api("/api/admin/users", { method: "POST", body });
      toast(t("user_created"), true);
      closeUserModal();
      loadUsers();
    } catch (err) {
      errEl.textContent = err.message;
      show(errEl);
    }
  }
}

function confirmDeleteUser(userId) {
  if (!confirm(t("delete_user_confirm"))) return;
  deleteUser(userId);
}

async function deleteUser(userId) {
  try {
    await api("/api/admin/users/" + encodeURIComponent(userId), {
      method: "DELETE",
    });
    toast(t("user_deleted"), true);
    loadUsers();
  } catch (err) {
    toast(err.message, false);
  }
}

// ── Journal ───────────────────────────────────────────────────────────────

/** Called when navigating to the journal page. Sets defaults then loads. */
function initJournalPage() {
  setJournalDefaultDates();
  void loadJournalUserFilter();
  loadJournal(0);
}

/** Set From = 2025-01-01, To = today (always resets when navigating to journal). */
function setJournalDefaultDates() {
  const fromEl = $("journal-filter-from");
  const toEl = $("journal-filter-to");
  if (fromEl) fromEl.value = "2025-01-01";
  if (toEl) toEl.value = new Date().toISOString().slice(0, 10);
}

/** Populate the verifier filter from the admin users list. */
async function loadJournalUserFilter() {
  const select = $("journal-filter-user");
  if (!select) return;
  const current = select.value;
  while (select.options.length > 1) select.remove(1);
  try {
    const users = await api("/api/admin/users");
    (users || []).forEach((u) => {
      const opt = document.createElement("option");
      opt.value = u.email;
      opt.textContent = u.email;
      select.appendChild(opt);
    });
    if (current) select.value = current;
  } catch (_) {}
}

async function loadJournal(offset) {
  journalOffset = offset || 0;
  journalLimit = parseInt($("journal-limit-select")?.value) || journalLimit;
  const userId = $("journal-filter-user")?.value || "";
  const dateFrom = $("journal-filter-from")?.value || "";
  const dateTo = $("journal-filter-to")?.value || "";

  let qs = `?limit=${journalLimit}&offset=${journalOffset}`;
  if (userId) qs += "&user_id=" + encodeURIComponent(userId);
  if (dateFrom) qs += "&date_from=" + encodeURIComponent(dateFrom + "T00:00:00Z");
  if (dateTo) qs += "&date_to=" + encodeURIComponent(dateTo + "T23:59:59Z");

  try {
    const entries = await api("/api/admin/journal" + qs);
    renderJournal(entries);
  } catch (err) {
    const tbody = $("journal-tbody");
    tbody.innerHTML = `<tr><td colspan="4" class="text-center text-white/40 py-6">${t("no_journal")}</td></tr>`;
  }
}

function renderJournal(entries) {
  const tbody = $("journal-tbody");
  if (!entries || entries.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-center text-white/40 py-6">${t("no_journal")}</td></tr>`;
    $("journal-prev").disabled = journalOffset === 0;
    $("journal-next").disabled = true;
    updateJournalPageInfo();
    return;
  }

  tbody.innerHTML = entries
    .map((e) => {
      const time = new Date(e.created_at).toLocaleString();
      const verifier = escapeHtml(e.qrcode_app_user_email || e.verifier || "—");
      const credential = escapeHtml(e.doc_type || e.namespace || "—");
      const statusBadge = e.success
        ? `<span class="text-green-400 font-semibold">✓</span>`
        : `<span class="text-red-400 font-semibold">✗</span>`;
      return `<tr>
        <td class="whitespace-nowrap">${time}</td>
        <td class="max-w-[220px] truncate" title="${escapeHtml(e.qrcode_app_user_email || e.verifier || "")}">${verifier}</td>
        <td class="max-w-[200px] truncate" title="${escapeHtml(e.doc_type || e.namespace || "")}">${credential}</td>
        <td class="text-center">${statusBadge}</td>
      </tr>`;
    })
    .join("");

  $("journal-prev").disabled = journalOffset === 0;
  $("journal-next").disabled = entries.length < journalLimit;
  updateJournalPageInfo();
}

function updateJournalPageInfo() {
  const page = Math.floor(journalOffset / journalLimit) + 1;
  $("journal-page-info").textContent = `${t("page")}&nbsp;${page}`;
}

function journalPage(dir) {
  const newOffset = journalOffset + dir * journalLimit;
  if (newOffset < 0) return;
  loadJournal(newOffset);
}

function clearJournalFilters() {
  const filterUser = $("journal-filter-user");
  const limitEl = $("journal-limit-select");
  if (filterUser) filterUser.value = "";
  if (limitEl) { limitEl.value = "10"; journalLimit = 10; }
  setJournalDefaultDates();
  loadJournal(0);
}

// ── Settings ──────────────────────────────────────────────────────────────

async function loadSettings() {
  try {
    const settings = await api("/api/settings");
    $("settings-app-name").value = settings.app_name || "";
    $("settings-logo-url").value = settings.logo_url || "";
  } catch (_) {}

  // Language
  const langSelect = $("settings-language");
  if (langSelect) {
    const saved = getSavedLang();
    langSelect.value = saved || "default";
  }

  // Load claims settings from localStorage
  loadClaimsSettings();
}

function loadClaimsSettings() {
  try {
    const pidClaims = JSON.parse(
      localStorage.getItem("verifier_app_pid_claims") ||
        JSON.stringify(["age_over_18", "portrait"])
    );
    document.querySelectorAll(".pid-claim-cb").forEach((cb) => {
      cb.checked = pidClaims.includes(cb.value);
    });
  } catch (_) {}

  try {
    const mdlClaims = JSON.parse(
      localStorage.getItem("verifier_app_mdl_claims") ||
        JSON.stringify(["age_over_18", "portrait"])
    );
    document.querySelectorAll(".mdl-claim-cb").forEach((cb) => {
      cb.checked = mdlClaims.includes(cb.value);
    });
  } catch (_) {}
}

async function saveSettings() {
  // Validate claims
  const pidChecked = document.querySelectorAll(".pid-claim-cb:checked").length;
  const mdlChecked = document.querySelectorAll(".mdl-claim-cb:checked").length;
  if (pidChecked === 0 || mdlChecked === 0) {
    toast(
      i18n["claims_min_one"] || "Select at least one claim per credential type.",
      false
    );
    return;
  }

  // Save display settings to server (admin only)
  if (currentUser?.role === "admin") {
    try {
      const body = {
        app_name: $("settings-app-name").value.trim(),
        logo_url: $("settings-logo-url").value.trim(),
      };
      await api("/api/admin/settings", { method: "PUT", body });
    } catch (err) {
      toast(err.message, false);
      return;
    }
  }

  // Save language preference locally
  const langSelect = $("settings-language");
  if (langSelect) {
    const lang = langSelect.value;
    setSavedLang(lang);
    const effectiveLang = lang === "default" ? detectBrowserLang() : lang;
    if (effectiveLang !== currentLang) {
      await loadI18n(effectiveLang);
      buildNav();
    }
  }

  // Save claims settings locally
  const pidClaims = [];
  document.querySelectorAll(".pid-claim-cb:checked").forEach((cb) => {
    pidClaims.push(cb.value);
  });
  localStorage.setItem("verifier_app_pid_claims", JSON.stringify(pidClaims));

  const mdlClaims = [];
  document.querySelectorAll(".mdl-claim-cb:checked").forEach((cb) => {
    mdlClaims.push(cb.value);
  });
  localStorage.setItem("verifier_app_mdl_claims", JSON.stringify(mdlClaims));

  // Re-apply branding
  await applyBranding();

  toast(t("settings_saved"), true);
}

// ── App init ──────────────────────────────────────────────────────────────

async function initApp() {
  // Load language
  const lang = getEffectiveLang();
  await loadI18n(lang);

  // Apply branding (also fetches server settings)
  await applyBranding();

  // Check setup status
  try {
    const status = await api("/api/setup/status");
    if (!status.bootstrapped) {
      showBootstrapPage();
      return;
    }
  } catch (_) {
    // If setup check fails, try login
  }

  // Try to resume session
  try {
    const user = await api("/api/auth/me");
    if (user) {
      currentUser = user;
      await onAuthenticated();
      return;
    }
  } catch (_) {
    // Not authenticated
  }

  showLoginPage();
}

// ── Expose globals for inline handlers ────────────────────────────────────
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

// ── Start ─────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", initApp);
