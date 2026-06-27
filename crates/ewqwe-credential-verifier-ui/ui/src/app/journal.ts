/**
 * Journal — audit log of verification attempts.
 *
 * Depends on: state (DOM helpers, journalOffset/…), i18n (t)
 */

import { apiFetch } from "../api.ts";
import type { JournalEntry, User } from "../types.ts";
import {
  $,
  escapeHtml,
  journalOffset,
  journalLimit,
  setJournalOffset,
  setJournalLimit,
} from "./state.ts";
import { t } from "./i18n.ts";

// ── Init ──────────────────────────────────────────────────────────────────

export function initJournalPage(): void {
  setJournalDefaultDates();
  void loadJournalUserFilter();
  void loadJournal(0);
}

function setJournalDefaultDates(): void {
  const fromEl = $("journal-filter-from") as HTMLInputElement | null;
  const toEl = $("journal-filter-to") as HTMLInputElement | null;
  if (fromEl) fromEl.value = "2026-01-01";
  if (toEl) toEl.value = new Date().toISOString().slice(0, 10);
}

// ── Filter helpers ────────────────────────────────────────────────────────

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

// ── Load & render ─────────────────────────────────────────────────────────

export async function loadJournal(offset: number): Promise<void> {
  setJournalOffset(offset ?? 0);
  const limitEl = $("journal-limit-select") as HTMLSelectElement | null;
  if (limitEl) setJournalLimit(parseInt(limitEl.value) || journalLimit);

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
  if (entries.length === 0) return '<span class="text-white/40">\u2014</span>';

  /** Claim keys whose values are raw binary encoded as base64. */
  const IMAGE_CLAIMS = new Set([
    "portrait",
    "signature",
    "signature_usual_mark",
  ]);

  return entries
    .map(([k, v]) => {
      // Image claims: render as a thumbnail
      if (IMAGE_CLAIMS.has(k) && typeof v === "string" && v.length > 0) {
        const standardBase64 = v.replace(/-/g, "+").replace(/_/g, "/");
        const mimeType = detectImageMimeType(standardBase64);
        // Browsers cannot render JPEG 2000 — show label instead of broken image
        if (mimeType === "image/jp2") {
          return `<span class="text-white/40 text-xs">${escapeHtml(k)}</span>`;
        }
        const src = `data:${mimeType};base64,${standardBase64}`;
        return `<span class="inline-flex"><img src="${src}" alt="" class="claim-thumbnail cursor-pointer" /></span>`;
      }

      if (typeof v === "boolean") {
        const icon = v ? "\u2713" : "\u2717";
        const cls = v ? "text-green-400" : "text-red-400";
        return `<span class="${cls} text-xs" title="${escapeHtml(k)}">${icon}&thinsp;${escapeHtml(k)}</span>`;
      }
      return `<span class="text-white/60 text-xs">${escapeHtml(k)}: ${escapeHtml(String(v)).slice(0, 30)}</span>`;
    })
    .join('<span class="text-white/25 mx-1">\u00b7</span>');
}

function detectImageMimeType(base64Std: string): string {
  try {
    const padded = base64Std.padEnd(
      base64Std.length + ((4 - (base64Std.length % 4)) % 4),
      "=",
    );
    const raw = atob(padded);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);

    if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff)
      return "image/jpeg";
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e)
      return "image/png";
    if (
      bytes[0] === 0x00 &&
      bytes[1] === 0x00 &&
      bytes[2] === 0x00 &&
      bytes[3] === 0x0c &&
      bytes[4] === 0x6a &&
      bytes[5] === 0x50
    )
      return "image/jp2";
    return "image/jpeg";
  } catch {
    return "image/jpeg";
  }
}

function renderJournal(entries: JournalEntry[]): void {
  const tbody = $("journal-tbody");
  if (!tbody) return;

  const prevBtn = $("journal-prev") as HTMLButtonElement | null;
  const nextBtn = $("journal-next") as HTMLButtonElement | null;

  const setDisabled = (btn: HTMLElement | null, val: boolean) => {
    if (btn) (btn as HTMLButtonElement).disabled = val;
  };

  if (!entries || entries.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-center text-white/40 py-6">${t("no_journal")}</td></tr>`;
    setDisabled(prevBtn, journalOffset === 0);
    setDisabled(nextBtn, true);
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

  setDisabled(prevBtn, journalOffset === 0);
  setDisabled(nextBtn, entries.length < journalLimit);
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
    setJournalLimit(10);
  }
  setJournalDefaultDates();
  void loadJournal(0);
}
