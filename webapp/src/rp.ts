import type { DebugLogger } from "./debug.ts";
import type {
  OpenID4VPRequest,
  OpenID4VPResponse,
  VerificationResult,
} from "./types.ts";
import { getClaimsForType, getDefaultClaims } from "./config.ts";
import {
  buildPresentationRequest,
  requestCredentials,
  sendToBackend,
} from "./credentials.ts";

/**
 * Relying Party Application - Main controller
 */
export class RelyingPartyApp {
  private logger: DebugLogger;
  private selectedCredentialType: string = "mdl";
  private selectedClaims: Set<string> = new Set();
  private selectedProtocol: string = "w3c-dc";
  private currentRequest: OpenID4VPRequest | null = null;
  private currentResponse: OpenID4VPResponse | null = null;

  constructor(logger: DebugLogger) {
    this.logger = logger;
  }

  initialize(): void {
    this.setupEventListeners();
    this.checkAPISupport();
    this.renderClaims();
    this.updateRequestPreview();

    // Initialize with default claims
    getDefaultClaims(this.selectedCredentialType).forEach((claim) => {
      this.selectedClaims.add(claim);
    });
    this.updateClaimsUI();
  }

  private setupEventListeners(): void {
    // Credential type buttons
    document.querySelectorAll(".credential-type-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const target = e.currentTarget as HTMLElement;
        const type = target.dataset.type;
        if (type) {
          this.selectCredentialType(type);
        }
      });
    });

    // Protocol selection
    document
      .getElementById("protocol-select")
      ?.addEventListener("change", (e) => {
        this.selectedProtocol = (e.target as HTMLSelectElement).value;
        this.updateProtocolDescription();
        this.updateRequestPreview();
      });

    // Initialize protocol description
    this.updateProtocolDescription();

    // Request credentials button
    document
      .getElementById("request-credentials-btn")
      ?.addEventListener("click", () => {
        this.handleCredentialRequest();
      });

    // Show request JSON toggle
    document
      .getElementById("show-request-btn")
      ?.addEventListener("click", () => {
        const preview = document.getElementById("request-preview");
        preview?.classList.toggle("hidden");
      });

    // Toggle debug result
    document
      .getElementById("toggle-debug-result")
      ?.addEventListener("click", () => {
        const debug = document.getElementById("debug-result");
        debug?.classList.toggle("hidden");
      });

    // New request button
    document
      .getElementById("new-request-btn")
      ?.addEventListener("click", () => {
        this.resetUI();
      });
  }

  private updateProtocolDescription(): void {
    const descEl = document.getElementById("protocol-description");
    if (!descEl) return;

    const descriptions: Record<string, string> = {
      "w3c-dc": "Uses navigator.credentials.get() with the wallet extension",
      openid4vp:
        "OpenID for Verifiable Presentations 1.0 - cross-device flow with QR code (coming soon)",
      preview: "Legacy preview protocol for testing",
    };

    descEl.textContent = descriptions[this.selectedProtocol] || "";
  }

  private selectCredentialType(type: string): void {
    this.selectedCredentialType = type;
    this.selectedClaims.clear();

    // Update UI
    document.querySelectorAll(".credential-type-btn").forEach((btn) => {
      btn.classList.toggle(
        "active",
        (btn as HTMLElement).dataset.type === type,
      );
    });

    // Re-render claims and select defaults
    this.renderClaims();
    getDefaultClaims(type).forEach((claim) => {
      this.selectedClaims.add(claim);
    });
    this.updateClaimsUI();
    this.updateRequestPreview();

    this.logger.log(`Selected credential type: ${type}`);
  }

  private renderClaims(): void {
    const container = document.getElementById("claims-selection");
    if (!container) return;

    const claims = getClaimsForType(this.selectedCredentialType);

    container.innerHTML = claims
      .map(
        (claim) => `
        <label class="claim-checkbox" data-claim="${claim.id}">
          <input type="checkbox" value="${claim.id}" />
          <span class="text-sm">${claim.name}</span>
        </label>
      `,
      )
      .join("");

    // Add event listeners to checkboxes
    container.querySelectorAll("input[type='checkbox']").forEach((checkbox) => {
      checkbox.addEventListener("change", (e) => {
        const target = e.target as HTMLInputElement;
        if (target.checked) {
          this.selectedClaims.add(target.value);
        } else {
          this.selectedClaims.delete(target.value);
        }
        this.updateClaimsUI();
        this.updateRequestPreview();
      });
    });
  }

  private updateClaimsUI(): void {
    document.querySelectorAll(".claim-checkbox").forEach((label) => {
      const claimId = (label as HTMLElement).dataset.claim;
      const checkbox = label.querySelector(
        "input[type='checkbox']",
      ) as HTMLInputElement;
      const isSelected = claimId && this.selectedClaims.has(claimId);

      label.classList.toggle("selected", isSelected || false);
      if (checkbox) {
        checkbox.checked = isSelected || false;
      }
    });
  }

  private updateRequestPreview(): void {
    const requestJson = document.getElementById("request-json");
    if (!requestJson) return;

    try {
      const request = buildPresentationRequest(
        this.selectedCredentialType,
        Array.from(this.selectedClaims),
        this.selectedProtocol,
      );
      this.currentRequest = request;
      requestJson.textContent = JSON.stringify(request, null, 2);
    } catch (error) {
      requestJson.textContent = `Error building request: ${error}`;
    }
  }

  private checkAPISupport(): void {
    const statusEl = document.getElementById("api-status");
    if (!statusEl) return;

    const checks = [
      {
        name: "Digital Credentials API",
        supported: typeof globalThis.DigitalCredential !== "undefined",
        icon: "🔐",
        infoUrl: "https://www.w3.org/TR/digital-credentials/",
      },
      {
        name: "Credential Management",
        supported: "credentials" in navigator,
        icon: "📋",
        infoUrl:
          "https://developer.mozilla.org/docs/Web/API/Credential_Management_API",
      },
      {
        name: "Secure Context",
        supported: globalThis.isSecureContext,
        icon: "🔒",
        infoUrl:
          "https://developer.mozilla.org/docs/Web/Security/Secure_Contexts",
      },
      {
        name: "Crypto API",
        supported:
          typeof crypto !== "undefined" &&
          typeof crypto.randomUUID === "function",
        icon: "🔑",
        infoUrl: "https://developer.mozilla.org/docs/Web/API/Crypto",
      },
    ];

    statusEl.innerHTML = checks
      .map(
        (check) => `
        <div class="bg-white/5 rounded-lg p-3 text-center relative">
          <a href="${check.infoUrl}" target="_blank" rel="noopener noreferrer" class="absolute top-2 right-2 text-gray-500/60 hover:text-gray-400 transition-colors text-xs" aria-label="Learn more about ${check.name}">
            ⓘ
          </a>
          <div class="text-2xl mb-1">${check.icon}</div>
          <div class="text-xs text-gray-400">${check.name}</div>
          <div class="${
            check.supported ? "text-green-400" : "text-amber-400"
          } text-sm font-medium">
            ${check.supported ? "✓ Supported" : "⚠ Limited"}
          </div>
        </div>
      `,
      )
      .join("");

    this.logger.log("API support checked", checks);
  }

  private async handleCredentialRequest(): Promise<void> {
    if (!this.currentRequest) {
      this.logger.error("No request configured");
      return;
    }

    if (this.selectedClaims.size === 0) {
      alert("Please select at least one claim to request");
      return;
    }

    // Show loading state
    const btn = document.getElementById(
      "request-credentials-btn",
    ) as HTMLButtonElement;
    const originalContent = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `
      <svg class="animate-spin w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
      </svg>
      Requesting...
    `;

    try {
      this.logger.log("Starting credential request");

      // Request credentials
      const response = await requestCredentials(
        this.currentRequest,
        this.logger,
      );

      if (!response) {
        throw new Error("Request was cancelled or failed");
      }

      this.currentResponse = response;

      // Send to backend for verification (proxies to Credential Verifier)
      const verificationResult = await sendToBackend(
        response,
        this.currentRequest,
        this.logger,
      );

      // Display the result
      this.displayVerificationResult(verificationResult, response);
    } catch (error) {
      this.logger.error("Credential request failed", error);
      this.displayError(
        error instanceof Error ? error.message : "Unknown error",
      );
    } finally {
      btn.disabled = false;
      btn.innerHTML = originalContent;
    }
  }

  private displayVerificationResult(
    result: VerificationResult,
    response: OpenID4VPResponse,
  ): void {
    const resultSection = document.getElementById("verification-result");
    const resultIcon = document.getElementById("result-icon");
    const resultTitle = document.getElementById("result-title");
    const resultContent = document.getElementById("result-content");
    const rawResponse = document.getElementById("raw-response");
    const verificationDetails = document.getElementById("verification-details");

    if (!resultSection || !resultIcon || !resultTitle || !resultContent) return;

    resultSection.classList.remove("hidden");
    resultSection.scrollIntoView({ behavior: "smooth" });

    if (result.success) {
      resultIcon.setAttribute("class", "w-6 h-6 mr-3 text-green-400");
      resultIcon.innerHTML = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />`;
      resultTitle.textContent = "Verification Successful";
      resultTitle.setAttribute("class", "result-success");

      // Render claims
      const claimsHtml = result.claims
        ? Object.entries(result.claims)
            .map(
              ([key, value]) => `
              <div class="flex justify-between items-center py-2 border-b border-white/10">
                <span class="text-gray-400">${this.formatClaimName(key)}</span>
                <span class="font-medium">${this.formatClaimValue(value)}</span>
              </div>
            `,
            )
            .join("")
        : "";

      resultContent.innerHTML = `
        <div class="bg-green-500/20 border border-green-500/50 rounded-lg p-4 mb-4">
          <div class="flex items-center">
            <svg class="w-5 h-5 text-green-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span class="text-green-400 font-medium">${result.message}</span>
          </div>
        </div>
        <h4 class="text-sm font-medium text-gray-400 mb-3">Verified Claims</h4>
        <div class="bg-white/5 rounded-lg p-4">
          ${claimsHtml || "<p class='text-gray-500'>No claims returned</p>"}
        </div>
      `;
    } else {
      resultIcon.setAttribute("class", "w-6 h-6 mr-3 text-red-400");
      resultIcon.innerHTML = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />`;
      resultTitle.textContent = "Verification Failed";
      resultTitle.setAttribute("class", "result-error");

      const errorsHtml = result.errors
        ? result.errors
            .map((err) => `<li class="text-red-400">${err}</li>`)
            .join("")
        : "";

      resultContent.innerHTML = `
        <div class="bg-red-500/20 border border-red-500/50 rounded-lg p-4">
          <div class="flex items-start">
            <svg class="w-5 h-5 text-red-400 mr-2 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <p class="text-red-400 font-medium">${result.message}</p>
              ${
                errorsHtml
                  ? `<ul class="mt-2 list-disc list-inside text-sm">${errorsHtml}</ul>`
                  : ""
              }
            </div>
          </div>
        </div>
      `;
    }

    // Populate debug information
    if (rawResponse) {
      rawResponse.textContent = JSON.stringify(response, null, 2);
    }
    if (verificationDetails && result.verificationDetails) {
      verificationDetails.textContent = JSON.stringify(
        result.verificationDetails,
        null,
        2,
      );
    }
  }

  private displayError(message: string): void {
    this.displayVerificationResult(
      {
        success: false,
        message: "Request failed",
        errors: [message],
      },
      {
        vp_token: "",
        presentation_submission: {
          id: "",
          definition_id: "",
          descriptor_map: [],
        },
      },
    );
  }

  private formatClaimName(key: string): string {
    return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  }

  private formatClaimValue(value: unknown): string {
    if (value === null || value === undefined) {
      return "—";
    }
    if (typeof value === "boolean") {
      return value ? "Yes ✓" : "No ✗";
    }
    if (Array.isArray(value)) {
      return value.join(", ");
    }
    return String(value);
  }

  private resetUI(): void {
    document.getElementById("verification-result")?.classList.add("hidden");
    document.getElementById("debug-result")?.classList.add("hidden");
    this.currentResponse = null;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
}
