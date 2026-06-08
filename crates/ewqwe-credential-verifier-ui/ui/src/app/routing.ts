/**
 * Navigation — nav items definition, drawer open/close, and nav bar building.
 *
 * Depends on: state (DOM helpers, currentUser, currentPage), i18n (t)
 */

import { $, hide, show, currentUser, currentPage } from "./state.ts";
import { t } from "./i18n.ts";

// ── Navigation items ──────────────────────────────────────────────────────

export interface NavItem {
  id: string;
  icon: string;
  label: string;
}

export const NAV_ITEMS_ADMIN: NavItem[] = [
  { id: "home", icon: "🏠", label: "home" },
  { id: "users", icon: "👥", label: "users" },
  { id: "journal", icon: "📋", label: "journal" },
  { id: "settings", icon: "⚙️", label: "settings" },
];

export const NAV_ITEMS_VERIFIER: NavItem[] = [
  { id: "home", icon: "🏠", label: "home" },
];

// ── Build navigation bar ──────────────────────────────────────────────────

export function buildNav(): void {
  if (!currentUser) return;
  const items =
    currentUser.role === "admin" ? NAV_ITEMS_ADMIN : NAV_ITEMS_VERIFIER;

  const renderItems = (container: HTMLElement | null) => {
    if (!container) return;
    container.innerHTML = "";
    items.forEach((item) => {
      const btn = document.createElement("button");
      btn.className = "nav-link" + (currentPage === item.id ? " active" : "");
      btn.innerHTML = `<span>${item.icon}</span> <span data-i18n="${item.label}">${t(item.label)}</span>`;
      btn.onclick = () => {
        // navigateTo is on window so inline HTML onclick works
        (window as any).navigateTo(item.id);
        closeDrawer();
      };
      container.appendChild(btn);
    });
    const logoutBtn = document.createElement("button");
    logoutBtn.className = "nav-link text-red-300/70";
    logoutBtn.innerHTML = `<span>🚪</span> <span data-i18n="logout">${t("logout")}</span>`;
    logoutBtn.onclick = () => (window as any).doLogout();
    container.appendChild(logoutBtn);
  };

  renderItems($("topbar-nav"));
  renderItems($("drawer-nav"));
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
