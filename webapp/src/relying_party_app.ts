import type { DebugLogger } from "./debug.ts";
import type {
  CredentialType,
  InitTransactionRequest,
  OpenID4VPResponse,
  VerifyResponse,
} from "@ewqwe/digital-identity";
import {
  buildInitTransactionRequest,
  getClaimsForType,
  getDefaultClaims,
  getProfileForType,
} from "@ewqwe/digital-identity";
import { requestCredentials, sendToBackend } from "./credentials.ts";

/**
 * Relying Party Application - Main controller
 */
export class RelyingPartyApp {
  private logger: DebugLogger;
  private selectedCredentialType: CredentialType = "proof-of-age";
  private selectedClaims: Set<string> = new Set();
  private selectedProtocol: string = "w3c-dc-fallback";
  private currentRequest: InitTransactionRequest | null = null;
  private currentResponse: OpenID4VPResponse | null = null;

  constructor(logger: DebugLogger) {
    this.logger = logger;
  }

  initialize(): void {
    this.setupEventListeners();
    this.checkAPISupport();
    this.updateProtocolDescription();
    this.renderClaims();
    this.updateProfileInfo();

    // Initialize with default claims before building the request,
    // so currentRequest is never created with an empty claims list.
    getDefaultClaims(this.selectedCredentialType).forEach((claim) => {
      this.selectedClaims.add(claim);
    });
    this.updateClaimsUI();
    this.updateInitTransactionRequest();

    // Restore any verification result that survived a page navigation
    // (same-device flow can trigger a brief page reload when the wallet
    // uses an https:// authorization-request URI as the deep link).
    const saved = sessionStorage.getItem("verificationResult");
    if (saved) {
      try {
        const { result, response } = JSON.parse(saved) as {
          result: VerifyResponse;
          response: OpenID4VPResponse;
        };
        this.logger.log("Restoring verification result from sessionStorage");
        this.displayVerificationResult(result, response);
      } catch (e) {
        this.logger.error("Failed to restore verification result", e);
        sessionStorage.removeItem("verificationResult");
      }
    }
  }

  private setupEventListeners(): void {
    // Credential type buttons
    document.querySelectorAll(".credential-type-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const target = e.currentTarget as HTMLElement;
        const type = target.dataset.type as CredentialType | undefined;
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
        console.log("Selected protocol:", this.selectedProtocol);
        this.updateProtocolDescription();
        this.updateInitTransactionRequest();
      });

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

  /**
   * Update the protocol description based on the selected protocol
   */
  private updateProtocolDescription(): void {
    const descEl = document.getElementById("protocol-description");
    if (!descEl) return;

    const descriptions: Record<string, string> = {
      "w3c-dc-fallback":
        "Tries W3C Digital Credentials API first, falls back to OpenID4VP if unavailable",
      "w3c-dc": "Uses navigator.credentials.get() with the wallet extension",
      "openid4vp-cross-device":
        "OpenID4VP 1.0 cross-device flow - scan QR code with mobile wallet (EUDI Wallet)",
      "openid4vp-same-device":
        "OpenID4VP 1.0 same-device flow - opens wallet app via deep link (mobile browsers)",
      simulated:
        "Simulates credential flow without calling any wallet (for testing)",
    };

    descEl.textContent = descriptions[this.selectedProtocol] || "";
  }

  /**
   * Select a credential type and update the UI accordingly
   * - Update selected claims based on defaults for the new type
   * - Rebuild the transaction init request with the new type and claims
   * - Update the profile information display
   * @param type The credential type to select
   */
  private selectCredentialType(type: CredentialType): void {
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
    this.updateInitTransactionRequest();
    this.updateProfileInfo();

    this.logger.log(`Selected credential type: ${type}`);
  }

  /**
   * Update the profile information display based on selected credential type
   */
  private updateProfileInfo(): void {
    const profileContainer = document.getElementById("profile-info");
    if (!profileContainer) return;

    const profile = getProfileForType(this.selectedCredentialType);
    if (!profile) {
      profileContainer.innerHTML = "";
      return;
    }

    const isHaip = profile.id === "haip";
    const badgeColor = isHaip ? "bg-blue-600" : "bg-green-600";
    const borderColor = isHaip ? "border-blue-500/30" : "border-green-500/30";
    const bgColor = isHaip ? "bg-blue-950/30" : "bg-green-950/30";

    profileContainer.innerHTML = `
      <div class="rounded-lg ${bgColor} ${borderColor} border p-4 mb-6">
        <div class="flex items-center gap-2 mb-3">
          <span class="px-2 py-1 ${badgeColor} text-xs font-semibold rounded-full">${profile.name}</span>
          <span class="text-gray-400 text-sm">${profile.description}</span>
        </div>
        <div class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span class="text-gray-500">Client ID Scheme:</span>
            <span class="ml-2 text-white font-mono">${profile.clientIdScheme}</span>
          </div>
          <div>
            <span class="text-gray-500">Request Format:</span>
            <span class="ml-2 text-white font-mono">${profile.requestFormat === "jar" ? "Signed JAR" : "Plain JSON"}</span>
          </div>
          <div>
            <span class="text-gray-500">Response Mode:</span>
            <span class="ml-2 text-white font-mono">${profile.responseMode}</span>
          </div>
          <div>
            <span class="text-gray-500">URL Scheme:</span>
            <span class="ml-2 text-white font-mono">${profile.urlSchemes[0]}</span>
          </div>
        </div>
      </div>
    `;
  }

  /**
   * Render the claim selection checkboxes based on the selected credential type.
   *
   * Adds event listeners to update the selected claims and rebuild the request
   * whenever a checkbox is toggled.
   */
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
        this.updateInitTransactionRequest();
      });
    });
  }

  /**
   * Update the UI to reflect which claims are currently selected.
   * This ensures that the checkboxes and labels are in sync with the selectedClaims set.
   */
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

  /**
   * Build the transaction init request based on the selected credential type and claims,
   * then update the displayed JSON in the UI.
   */
  private updateInitTransactionRequest(): void {
    const requestJson = document.getElementById("request-json");
    if (!requestJson) return;

    try {
      const request = buildInitTransactionRequest(
        this.selectedCredentialType,
        Array.from(this.selectedClaims),
      );
      this.currentRequest = request;
      requestJson.textContent = JSON.stringify(request, null, 2);
    } catch (error) {
      requestJson.textContent = `Error building request: ${error}`;
    }
  }

  /**
   * Check the support for various APIs and update the UI accordingly.
   */
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

  /**
   * Handle the credential request process, including UI updates and error handling.
   */
  private async handleCredentialRequest(): Promise<void> {
    if (!this.currentRequest) {
      this.logger.error("No request configured");
      return;
    }

    if (this.selectedClaims.size === 0) {
      alert("Please select at least one claim to request");
      return;
    }

    // Disable button and show spinner
    const btn_request = document.getElementById(
      "request-credentials-btn",
    ) as HTMLButtonElement;
    btn_request.classList.replace("flex", "hidden");
    const btn_requesting = document.getElementById(
      "requesting-credentials-btn",
    ) as HTMLButtonElement;
    btn_requesting.classList.replace("hidden", "flex");

    try {
      this.logger.log(
        "Starting credential request with protocol:",
        this.selectedProtocol,
      );

      // Request credentials
      this.logger.log("Calling requestCredentials…");
      const response = await requestCredentials(
        this.currentRequest,
        this.selectedProtocol,
        this.logger,
      );
      this.logger.log(
        "requestCredentials returned",
        response ? "response" : "null",
      );

      if (!response) {
        throw new Error("Request was cancelled or no credentials found");
      }

      this.currentResponse = response;

      // Send to backend for verification (proxies to Credential Verifier)
      this.logger.log("Sending to backend for verification…");
      const verificationResult = await sendToBackend(
        response,
        this.currentRequest,
        this.logger,
      );
      this.logger.log("Backend verification result", {
        success: verificationResult.success,
        message: verificationResult.message,
      });

      // Display the result
      this.displayVerificationResult(verificationResult, response);
    } catch (error) {
      this.logger.error("Credential request failed", error);
      this.displayError(
        error instanceof Error ? error.message : "Unknown error",
      );
    } finally {
      btn_requesting.classList.replace("flex", "hidden");
      btn_request.classList.replace("hidden", "flex");
    }
  }

  /**
   * Display the verification result in the UI, including success/failure status,
   * any returned claims, and debug information.
   *
   * Persists the result in sessionStorage to survive page reloads (e.g. from deep link flow).
   *
   * @param result The result of the verification process, including success status, message, claims, and any errors.
   * @param response The original OpenID4VP response received from the wallet, for debugging purposes.
   */
  private displayVerificationResult(
    result: VerifyResponse,
    response: OpenID4VPResponse,
  ): void {
    const resultSection = document.getElementById("verification-result");
    const resultIcon = document.getElementById("result-icon");
    const resultTitle = document.getElementById("result-title");
    const resultContent = document.getElementById("result-content");
    const rawResponse = document.getElementById("raw-response");
    const verificationDetails = document.getElementById("verification-details");

    if (!resultSection || !resultIcon || !resultTitle || !resultContent) {
      this.logger.error(
        "displayVerificationResult: one or more required DOM elements not found",
        {
          resultSection: !!resultSection,
          resultIcon: !!resultIcon,
          resultTitle: !!resultTitle,
          resultContent: !!resultContent,
        },
      );
      return;
    }

    // Persist so the result survives an accidental page reload
    try {
      sessionStorage.setItem(
        "verificationResult",
        JSON.stringify({ result, response }),
      );
    } catch {
      /* storage full or private browsing */
    }

    this.logger.log("Displaying verification result", {
      success: result.success,
    });
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
      resultTitle.textContent = "Last Verification Failed";
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
    if (verificationDetails && result.verification_details) {
      verificationDetails.textContent = JSON.stringify(
        result.verification_details,
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

  /**
   * Format claim keys into more human-readable names.
   * E.g. "given_name" → "Given Name", "place_of_birth" → "Place Of Birth"
   */
  private formatClaimName(key: string): string {
    return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  }

  /**
   * Format claim values for display. Handles different data types (string, boolean, arrays, nested objects).
   * - Booleans are shown as "Yes ✓" or "No ✗"
   * - Arrays are joined with ", "
   * - Nested objects show non-empty leaf values joined by ", "
   * - Null/undefined values show as "—"
   */
  private formatClaimValue(value: unknown): string {
    if (value === null || value === undefined) {
      return "—";
    }
    if (typeof value === "boolean") {
      return value ? "Yes ✓" : "No ✗";
    }
    if (Array.isArray(value)) {
      return value.map((v) => this.formatClaimValue(v)).join(", ");
    }
    if (typeof value === "object") {
      // Nested object (e.g. place_of_birth: {country, region, locality})
      // Show non-empty leaf values joined by ", "
      const parts: string[] = [];
      for (const v of Object.values(value as Record<string, unknown>)) {
        if (v !== null && v !== undefined && v !== "") {
          parts.push(this.formatClaimValue(v));
        }
      }
      return parts.length > 0 ? parts.join(", ") : "—";
    }
    return String(value);
  }

  /**
   * Reset the UI to the initial state for a new request
   */
  private resetUI(): void {
    sessionStorage.removeItem("verificationResult");
    document.getElementById("verification-result")?.classList.add("hidden");
    document.getElementById("debug-result")?.classList.add("hidden");
    this.currentResponse = null;
    globalThis.scrollTo({ top: 0, behavior: "smooth" });
  }
}
