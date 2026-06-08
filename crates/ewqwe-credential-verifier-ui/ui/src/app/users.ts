/**
 * Users management — CRUD for verifier users.
 *
 * Depends on: state (DOM helpers, editingUserId), i18n (t)
 */

import { apiFetch } from "../api.ts";
import type { User } from "../types.ts";
import {
  $,
  hide,
  show,
  toast,
  editingUserId,
  escapeHtml,
  setEditingUserId,
} from "./state.ts";
import { t } from "./i18n.ts";

// ── Load & render ─────────────────────────────────────────────────────────

export async function loadUsers(): Promise<void> {
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

// ── Modal open/close ──────────────────────────────────────────────────────

export function openCreateUserModal(): void {
  setEditingUserId(null);
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
  setEditingUserId(userId);
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
  setEditingUserId(null);
}

// ── Form submit ───────────────────────────────────────────────────────────

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

// ── Delete ────────────────────────────────────────────────────────────────

export function confirmDeleteUser(userId: string): void {
  if (!confirm(t("delete_user_confirm"))) return;
  void deleteUser(userId);
}

async function deleteUser(userId: string): Promise<void> {
  try {
    await apiFetch<null>(`/admin/users/${encodeURIComponent(userId)}`, {
      method: "DELETE",
    });
    toast(t("user_deleted"), true);
    await loadUsers();
  } catch (err) {
    toast((err as Error).message, false);
  }
}
