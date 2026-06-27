/**
 * QR Code — display, credential type selection, and transaction polling.
 *
 * Depends on: state (DOM helpers, currentUser, pollTimer, …), i18n (t)
 */

import { apiFetch } from "../api.ts";
import type { QrResponse, QrStatus } from "../types.ts";
import {
  $,
  hide,
  show,
  toast,
  escapeHtml,
  currentUser,
  serverAllowedTypes,
  pollTimer,
  qrTypeSelectorWasVisible,
  setQrTypeSelectorWasVisible,
  setCurrentTransactionId,
  setPollTimer,
} from "./state.ts";
import { t } from "./i18n.ts";

// ── Setup QR page ─────────────────────────────────────────────────────────

export function setupQRPage(): void {
  if (!currentUser) return;

  const userTypes = currentUser.allowed_credential_types ?? [];
  const allTypes = [
    "proof-of-age",
    "mdl",
    "national-id",
    "france-identite-numerique",
  ];

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

// ── Helpers ──────────────────────────────────────────────────────────────

/**
 * Read the saved claims for a given credential type from localStorage.
 * Falls back to ["age_over_18"] when nothing has been saved yet.
 */
function getClaimsForCredentialType(credType: string): string[] {
  let storageKey: string;
  if (credType === "mdl") {
    storageKey = "verifier_ui_mdl_claims";
  } else if (credType === "france-identite-numerique") {
    storageKey = "verifier_ui_france_claims";
  } else {
    // "proof-of-age" and "national-id" both use pid claims
    storageKey = "verifier_ui_pid_claims";
  }

  try {
    return JSON.parse(localStorage.getItem(storageKey) ?? "null") as string[];
  } catch {
    return ["age_over_18"];
  }
}

/** Format a claim value for display — trims long strings, shows booleans/text. */
function formatClaimValue(val: unknown): string {
  if (typeof val === "boolean") return val ? "\u2713" : "\u2717";
  if (typeof val === "string") {
    // Truncate long strings (e.g. base64 portraits)
    return val.length > 60 ? val.slice(0, 57) + "\u2026" : val;
  }
  if (val === null || val === undefined) return "\u2014";
  return String(val);
}

/** Claim keys whose values are raw binary encoded as base64. */
const IMAGE_CLAIMS = new Set(["portrait", "signature", "signature_usual_mark"]);

/**
 * Render a single claim entry. Image claims (portrait) show an <img> instead of text.
 */
function renderClaimEntry(key: string, val: unknown): string {
  const label = escapeHtml(key);
  if (IMAGE_CLAIMS.has(key) && typeof val === "string" && val.length > 0) {
    // The portrait value from the mDoc credential is base64url-encoded
    // (CBOR byte strings use URL-safe base64). Convert to standard base64
    // for the data: URI, which does not understand base64url characters.
    const standardBase64 = val.replace(/-/g, "+").replace(/_/g, "/");
    const mimeType = detectImageMimeType(standardBase64);
    const src = `data:${mimeType};base64,${standardBase64}`;
    const altAttr = `${label}${mimeType === "image/jp2" ? " (JPEG 2000 — may not display)" : ""}`;
    return `
      <div class="flex justify-between items-center py-0.5">
        <span class="text-white/60">${label}</span>
        <img src="${src}" alt="${altAttr}" class="h-16 w-12 object-cover rounded" />
      </div>`;
  }
  return `
    <div class="flex justify-between items-center py-0.5">
      <span class="text-white/60">${label}</span>
      <span class="text-white text-right truncate max-w-[60%]">${escapeHtml(formatClaimValue(val))}</span>
    </div>`;
}

/**
 * Detect image MIME type from magic bytes encoded in standard base64.
 * Adds missing `=` padding before decoding.
 */
function detectImageMimeType(base64Std: string): string {
  try {
    // Restore padding — base64 length must be a multiple of 4
    const padded = base64Std.padEnd(
      base64Std.length + ((4 - (base64Std.length % 4)) % 4),
      "=",
    );
    // Decode the first 12 bytes (enough for all signatures below)
    const raw = atob(padded);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    // JPEG (SOI marker \xff\xd8\xff)
    if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
      return "image/jpeg";
    }
    // PNG
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e) {
      return "image/png";
    }
    // JPEG 2000
    if (
      bytes[0] === 0x00 &&
      bytes[1] === 0x00 &&
      bytes[2] === 0x00 &&
      bytes[3] === 0x0c &&
      bytes[4] === 0x6a &&
      bytes[5] === 0x50
    ) {
      return "image/jp2";
    }
    // WebP
    if (
      bytes[0] === 0x52 &&
      bytes[1] === 0x49 &&
      bytes[2] === 0x46 &&
      bytes[8] === 0x57 &&
      bytes[9] === 0x45 &&
      bytes[10] === 0x42 &&
      bytes[11] === 0x50
    ) {
      return "image/webp";
    }
    // GIF
    if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) {
      return "image/gif";
    }
    return "image/jpeg"; // best guess fallback
  } catch {
    return "image/jpeg"; // fallback
  }
}

// ── Generate QR ───────────────────────────────────────────────────────────

export async function generateQR(): Promise<void> {
  const select = $("qr-credential-type") as HTMLSelectElement;
  const credType = select.value;
  console.log("generateQR for credential_type", credType);

  hideAllQRStates();
  show("qr-area-loading");

  try {
    const claims = getClaimsForCredentialType(credType);
    const data = await apiFetch<QrResponse>("/qr/generate", {
      method: "POST",
      body: { credential_type: credType, claims },
    });

    setCurrentTransactionId(data.transaction_id);

    const typeSelector = $("qr-type-selector");
    const wasVisible =
      qrTypeSelectorWasVisible ||
      !!(typeSelector && !typeSelector.classList.contains("hidden"));
    setQrTypeSelectorWasVisible(wasVisible);
    hide("qr-type-selector");

    const selectedOpt = select.options[select.selectedIndex];
    const i18nKey = selectedOpt?.getAttribute("data-i18n");
    const typeLabel = i18nKey
      ? t(i18nKey)
      : (selectedOpt?.textContent?.trim() ?? "");
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
    if (cancelBtn && wasVisible) show(cancelBtn);

    startPolling(data.transaction_id);
  } catch (err) {
    hideAllQRStates();
    show("qr-area-empty");
    toast((err as Error).message, false);
  }
}

// ── Cancel / Reset QR ─────────────────────────────────────────────────────

export function cancelQR(): void {
  stopPolling();
  setCurrentTransactionId(null);
  resetQR();
}

export function resetQR(): void {
  stopPolling();
  setCurrentTransactionId(null);
  hideAllQRStates();
  show("qr-area-empty");
  if (qrTypeSelectorWasVisible) show("qr-type-selector");
  setQrTypeSelectorWasVisible(false);
  const titleEl = $("qr-title");
  if (titleEl) titleEl.textContent = t("credential_verification_qr");
}

// ── QR state helpers ──────────────────────────────────────────────────────

function hideAllQRStates(): void {
  [
    "qr-area-empty",
    "qr-area-loading",
    "qr-area-code",
    "qr-area-verified",
    "qr-area-failed",
  ].forEach(hide);
}

// ── Polling ───────────────────────────────────────────────────────────────

async function pollStatus(txId: string): Promise<void> {
  try {
    const data = await apiFetch<QrStatus>(
      `/qr/${encodeURIComponent(txId)}/status`,
    );
    const status = data.status;

    if (status === "verified" || status === "completed") {
      stopPolling();
      hideAllQRStates();

      // ── All verified claims ────────────────────────────────────
      const claimsContainer = $("qr-verified-claims");
      const claimsList = $("qr-claims-list");
      if (claimsContainer && claimsList && data.verified_claims) {
        const entries = Object.entries(data.verified_claims);
        if (entries.length > 0) {
          claimsList.innerHTML = entries
            .map(([key, val]) => renderClaimEntry(key, val))
            .join("");
          claimsContainer.classList.remove("hidden");
        } else {
          claimsContainer.classList.add("hidden");
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
          status === "expired"
            ? t("session_expired")
            : t("presentation_rejected");
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

function startPolling(txId: string): void {
  stopPolling();
  setPollTimer(setInterval(() => void pollStatus(txId), 2000));
}

function stopPolling(): void {
  if (pollTimer) {
    clearInterval(pollTimer);
    setPollTimer(null);
  }
}
