/**
 * EU Age Verification Wallet - Popup Script
 *
 * Handles the popup UI for credential management and display.
 */

import type { StoredCredential, CredentialType } from "../src/types";
import { CREDENTIAL_TYPE_CONFIGS } from "../src/types";

// Cross-browser runtime API
const runtime =
  typeof browser !== "undefined" ? browser.runtime : chrome.runtime;

// State
let credentials: StoredCredential[] = [];
let activeTab: CredentialType | "all" = "all";
let selectedCredential: StoredCredential | null = null;
let avProtocolRequest: string | null = null;

/**
 * Initialize popup
 */
async function init() {
  // Check for av:// protocol invocation
  checkAVProtocolRequest();

  await loadCredentials();
  setupEventListeners();
  render();

  // If opened via av:// protocol, show request handling UI
  if (avProtocolRequest) {
    handleAVProtocolRequest(avProtocolRequest);
  }
}

/**
 * Check if popup was opened via av:// protocol handler
 */
function checkAVProtocolRequest() {
  const urlParams = new URLSearchParams(window.location.search);
  const avParam = urlParams.get("av");
  if (avParam) {
    // The av param contains the full av:// URI
    avProtocolRequest = decodeURIComponent(avParam);
    console.log("[Wallet] Opened via av:// protocol:", avProtocolRequest);
  }
}

/**
 * Handle av:// protocol request
 * URI format: web+av://request?type=proof-of-age&claims=age_over_18,age_over_21
 */
function handleAVProtocolRequest(avUri: string) {
  try {
    // Parse the av:// URI
    const url = new URL(avUri.replace("web+av://", "https://av.local/"));
    const requestType = url.pathname.replace("/", "") || url.hostname;
    const type = url.searchParams.get("type") as CredentialType | null;
    const claimsParam = url.searchParams.get("claims");
    const claims = claimsParam ? claimsParam.split(",") : [];
    const returnUrl = url.searchParams.get("return");

    console.log("[Wallet] AV Protocol Request:", {
      requestType,
      type,
      claims,
      returnUrl,
    });

    // Filter to matching credentials
    if (type) {
      setActiveTab(type);
    }

    // Show a notification about the request
    const header = document.querySelector(".header h1");
    if (header) {
      header.innerHTML = `<span class="text-purple-400">🔐</span> Credential Request`;
    }

    // Add request info banner
    const container = document.querySelector(".container");
    if (container) {
      const banner = document.createElement("div");
      banner.className =
        "bg-purple-900/50 border border-purple-500/30 rounded-lg p-3 mb-4 text-sm";
      banner.innerHTML = `
        <div class="text-purple-200 font-medium mb-1">Age Verification Request</div>
        <div class="text-slate-300">
          ${type ? `Type: <span class="text-purple-300">${type}</span>` : ""}
          ${claims.length ? `<br>Claims: <span class="text-purple-300">${claims.join(", ")}</span>` : ""}
        </div>
      `;
      container.insertBefore(banner, container.firstChild?.nextSibling || null);
    }
  } catch (error) {
    console.error("[Wallet] Failed to parse av:// URI:", error);
  }
}

/**
 * Load credentials from background
 */
async function loadCredentials() {
  const response = await runtime.sendMessage({ type: "GET_CREDENTIALS" });
  credentials = response.credentials || [];
  updateCounts(response.counts);
}

/**
 * Update credential counts in UI
 */
function updateCounts(counts: Record<CredentialType, number>) {
  document.getElementById("count-mdl")!.textContent = String(
    counts["mdl"] || 0,
  );
  document.getElementById("count-pid")!.textContent = String(
    counts["national-id"] || 0,
  );
  document.getElementById("count-poa")!.textContent = String(
    counts["proof-of-age"] || 0,
  );
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
  // Tab buttons
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const tab = (e.target as HTMLElement).dataset.tab as
        | CredentialType
        | "all";
      setActiveTab(tab);
    });
  });

  // Reset button
  document.getElementById("reset-btn")?.addEventListener("click", async () => {
    if (confirm("Reset wallet to sample credentials?")) {
      await runtime.sendMessage({ type: "RESET_CREDENTIALS" });
      await loadCredentials();
      render();
    }
  });

  // Load samples button
  document
    .getElementById("load-samples-btn")
    ?.addEventListener("click", async () => {
      await runtime.sendMessage({ type: "RESET_CREDENTIALS" });
      await loadCredentials();
      render();
    });

  // Modal close
  document.getElementById("modal-close")?.addEventListener("click", closeModal);
  document
    .getElementById("credential-modal")
    ?.addEventListener("click", (e) => {
      if (e.target === e.currentTarget) closeModal();
    });

  // Modal delete
  document
    .getElementById("modal-delete")
    ?.addEventListener("click", async () => {
      if (selectedCredential && confirm("Delete this credential?")) {
        await runtime.sendMessage({
          type: "DELETE_CREDENTIAL",
          id: selectedCredential.id,
        });
        closeModal();
        await loadCredentials();
        render();
      }
    });
}

/**
 * Set active tab
 */
function setActiveTab(tab: CredentialType | "all") {
  activeTab = tab;

  // Update tab button styles using CSS .active class
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    const btnTab = (btn as HTMLElement).dataset.tab;
    if (btnTab === tab) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  render();
}

/**
 * Render credentials list
 */
function render() {
  const listEl = document.getElementById("credentials-list")!;
  const emptyEl = document.getElementById("empty-state")!;

  // Filter credentials by active tab
  const filtered =
    activeTab === "all"
      ? credentials
      : credentials.filter((c) => c.type === activeTab);

  if (filtered.length === 0) {
    listEl.innerHTML = "";
    emptyEl.classList.remove("hidden");
    return;
  }

  emptyEl.classList.add("hidden");
  listEl.innerHTML = filtered.map(renderCredentialCard).join("");

  // Add click handlers
  listEl.querySelectorAll(".credential-card").forEach((card) => {
    card.addEventListener("click", (e) => {
      const id = (e.currentTarget as HTMLElement).dataset.id;
      const cred = credentials.find((c) => c.id === id);
      if (cred) openModal(cred);
    });
  });
}

/**
 * Render a single credential card
 */
function renderCredentialCard(cred: StoredCredential): string {
  const config = CREDENTIAL_TYPE_CONFIGS[cred.type];
  const isExpired = new Date(cred.expiresAt) < new Date();
  const expiryDate = new Date(cred.expiresAt).toLocaleDateString();

  // Dark theme colors matching webapp glass morphism style
  const iconBgColor = {
    mdl: "bg-blue-500\\/20",
    "national-id": "bg-green-500\\/20",
    "proof-of-age": "bg-purple-500\\/20",
  }[cred.type];

  const iconColor = {
    mdl: "text-blue-400",
    "national-id": "text-green-400",
    "proof-of-age": "text-purple-400",
  }[cred.type];

  const icon = {
    mdl: `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" />`,
    "national-id": `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />`,
    "proof-of-age": `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />`,
  }[cred.type];

  return `
    <div class="credential-card cursor-pointer p-3"
         data-id="${cred.id}">
      <div class="flex items-start gap-3">
        <div class="w-10 h-10 rounded-lg ${iconBgColor} flex items-center justify-center">
          <svg class="w-5 h-5 ${iconColor}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            ${icon}
          </svg>
        </div>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2">
            <h3 class="font-medium text-sm truncate text-white">${cred.displayName}</h3>
            ${isExpired ? '<span class="px-1.5 py-0.5 text-xs bg-red-500\\/20 text-red-400 rounded">Expired</span>' : ""}
          </div>
          <p class="text-xs text-gray-400 truncate">${cred.issuer}</p>
          <p class="text-xs text-gray-500 mt-1">Expires: ${expiryDate}</p>
        </div>
        <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
        </svg>
      </div>
    </div>
  `;
}

/**
 * Open credential detail modal
 */
function openModal(cred: StoredCredential) {
  selectedCredential = cred;

  const config = CREDENTIAL_TYPE_CONFIGS[cred.type];

  document.getElementById("modal-title")!.textContent = cred.displayName;
  document.getElementById("modal-issuer")!.textContent = cred.issuer;

  // Render claims
  const claimsHtml = Object.entries(cred.claims)
    .filter(([_, value]) => value !== null && value !== undefined)
    .map(([key, value]) => {
      let displayValue: string;
      if (typeof value === "boolean") {
        displayValue = value ? "✓ Yes" : "✗ No";
      } else if (Array.isArray(value)) {
        displayValue = value
          .map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v)))
          .join(", ");
      } else if (typeof value === "object") {
        displayValue = JSON.stringify(value);
      } else {
        displayValue = String(value);
      }

      return `
        <div class="claim-row">
          <span class="claim-label">${formatClaimName(key)}</span>
          <span class="claim-value" title="${displayValue}">
            ${displayValue}
          </span>
        </div>
      `;
    })
    .join("");

  document.getElementById("modal-content")!.innerHTML = `
    <div class="modal-info-box">
      <div class="modal-info-row">
        <span>Type</span>
        <span class="font-mono">${config.displayName}</span>
      </div>
      <div class="modal-info-row">
        <span>DocType</span>
        <span class="font-mono text-xs">${cred.docType}</span>
      </div>
    </div>
    <h4 class="claims-heading">Claims</h4>
    ${claimsHtml}
  `;

  document.getElementById("credential-modal")!.classList.remove("hidden");
}

/**
 * Close modal
 */
function closeModal() {
  selectedCredential = null;
  document.getElementById("credential-modal")!.classList.add("hidden");
}

/**
 * Format claim name for display
 */
function formatClaimName(name: string): string {
  return name.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase());
}

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", init);
