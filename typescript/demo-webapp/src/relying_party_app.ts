import type { DebugLogger } from "./debug.ts";
import type {
  CredentialType,
  InitTransactionRequest,
  OpenID4VPResponse,
  ProfileId,
  VerifyResponse,
} from "@ewqwe/digital-identity";
import {
  buildInitTransactionRequest,
  CREDENTIAL_TYPES,
  decodeAttestation,
  getClaimsForType,
  getDefaultClaims,
  parseAttestation,
} from "@ewqwe/digital-identity";
import {
  isMobileDevice,
  requestCredentials,
  sendToBackend,
} from "./credentials.ts";

/**
 * Relying Party Application - Main controller
 */
/**
 * Protocol metadata for the info box — maps each protocol to its
 * request format, response mode, transport mechanism, and URL scheme / API.
 */
interface ProtocolInfo {
  requestFormat: string;
  responseMode: string;
  transport: string;
  urlScheme: string;
}

export class RelyingPartyApp {
  private logger: DebugLogger;
  private selectedCredentialType: CredentialType = "national-id";
  private selectedClaims: Set<string> = new Set();
  private selectedProtocol: string = RelyingPartyApp.getDeviceDefaultProtocol();
  private useX509SanDns: boolean = false;

  /**
   * Protocols allowed for each credential type.
   * Keys omitted from this map allow all protocols.
   */
  private static readonly ALLOWED_PROTOCOLS: Partial<
    Record<CredentialType, string[]>
  > = {
    "proof-of-age": ["openid4vp-same-device", "openid4vp-cross-device"],
  };

  /**
   * Returns the appropriate default protocol based on the user's device.
   * On mobile, same-device (deep link) is the natural flow.
   * On desktop/laptop, cross-device (QR code) is more practical.
   */
  private static getDeviceDefaultProtocol(): string {
    return isMobileDevice()
      ? "openid4vp-same-device"
      : "openid4vp-cross-device";
  }

  /** Protocol metadata for the info box. */
  private static readonly PROTOCOL_INFO: Record<string, ProtocolInfo> = {
    "w3c-dc-openid4vp": {
      requestFormat: "DC API request with protocol: openid4vp-v1-unsigned",
      responseMode: "dc_api — via W3C Digital Credentials API",
      transport: "W3C Digital Credentials API (navigator.credentials.get)",
      urlScheme: "W3C Digital Credentials API — no URL scheme involved",
    },
    "w3c-dc-iso-mdoc": {
      requestFormat: "DC API request with protocol: org-iso-mdoc (HPKE + CBOR)",
      responseMode: "dc_api — via W3C Digital Credentials API",
      transport: "W3C Digital Credentials API (navigator.credentials.get)",
      urlScheme: "W3C Digital Credentials API — no URL scheme involved",
    },
    "w3c-dc-fallback": {
      requestFormat: "Multiple protocols attempted in sequence",
      responseMode: "dc_api → direct_post",
      transport: "W3C Digital Credentials API → OpenID4VP cross-device",
      urlScheme: "DC API / URL scheme — depends on fallback step",
    },
    "openid4vp-cross-device": {
      requestFormat: "OpenID4VP Authorization Request (QR code)",
      responseMode: "direct_post — wallet POSTs to response_uri",
      transport: "Cross-device (QR code scan)",
      urlScheme: "openid4vp://, eudi-openid4vp://",
    },
    "openid4vp-same-device": {
      requestFormat: "OpenID4VP Authorization Request (redirect deep link)",
      responseMode: "fragment — response in redirect URL fragment",
      transport: "Same-device (deep link redirect)",
      urlScheme: "openid4vp://, eudi-openid4vp://",
    },
  };
  private currentRequest: InitTransactionRequest | null = null;
  private currentResponse: OpenID4VPResponse | null = null;

  constructor(logger: DebugLogger) {
    this.logger = logger;
  }

  initialize(): void {
    this.setupEventListeners();
    this.checkAPISupport();
    // Build protocol dropdown with only the options valid for the initial credential type
    this.buildProtocolOptions();
    // Sync the <select> element with the JS-computed default
    const protocolSelect = document.getElementById(
      "protocol-select",
    ) as HTMLSelectElement | null;
    if (protocolSelect) {
      protocolSelect.value = this.selectedProtocol;
    }
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
    this.updateX509SanDnsVisibility();

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
        void this.displayVerificationResult(result, response);
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
        this.logger.log("Selected protocol:", this.selectedProtocol);
        this.updateProtocolDescription();
        this.updateProfileInfo();
        this.updateInitTransactionRequest();
        this.updateX509SanDnsVisibility();
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

    // x509_san_dns client_id scheme toggle
    document
      .getElementById("use-x509-san-dns")
      ?.addEventListener("change", (e) => {
        this.useX509SanDns = (e.target as HTMLInputElement).checked;
        this.logger.log(
          "x509_san_dns scheme:",
          this.useX509SanDns ? "enabled" : "disabled",
        );
        this.updateProfileInfo();
        this.updateInitTransactionRequest();
      });
  }

  /**
   * Update the protocol description based on the selected protocol
   */
  private updateProtocolDescription(): void {
    const descEl = document.getElementById("protocol-description");
    if (!descEl) return;

    const descriptions: Record<string, string> = {
      "w3c-dc-openid4vp":
        "Annex C Sub-protocol B: OpenID4VP over DC API (openid4vp-v1-*) — default",
      "w3c-dc-iso-mdoc":
        "Annex C Sub-protocol A: Raw ISO mDoc via DC API (org-iso-mdoc / HPKE + CBOR)",
      "w3c-dc-fallback":
        "Tries Annex C Sub-protocol B, then Sub-protocol A, then OpenID4VP cross-device",
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
  /**
   * Build the protocol <select> options based on the current credential type.
   * Only protocols allowed for the credential type are included.
   * If the current protocol is not in the allowed set, it is reset to the default.
   */
  private buildProtocolOptions(): void {
    const select = document.getElementById(
      "protocol-select",
    ) as HTMLSelectElement | null;
    if (!select) return;

    const allowed = RelyingPartyApp.ALLOWED_PROTOCOLS[
      this.selectedCredentialType
    ] ?? [
      "w3c-dc-fallback",
      "openid4vp-same-device",
      "openid4vp-cross-device",
      "w3c-dc-openid4vp",
      "w3c-dc-iso-mdoc",
    ];

    // If current protocol is not allowed for this credential type, reset to device-appropriate default
    if (!allowed.includes(this.selectedProtocol)) {
      const deviceDefault = RelyingPartyApp.getDeviceDefaultProtocol();
      this.selectedProtocol = allowed.includes(deviceDefault)
        ? deviceDefault
        : allowed[0];
    }

    const optionLabels: Record<string, string> = {
      "w3c-dc-openid4vp": "Annex C Sub-protocol B: OpenID4VP over DC API",
      "w3c-dc-iso-mdoc": "Annex C Sub-protocol A: Raw ISO mDoc (HPKE + CBOR)",
      "w3c-dc-fallback": "Annex C with fallback to OpenID4VP",
      "openid4vp-cross-device": "OpenID4VP (Cross-Device / QR Code)",
      "openid4vp-same-device": "OpenID4VP (Same-Device / Deep Link)",
    };

    select.innerHTML = allowed
      .map(
        (value) =>
          `<option value="${value}">${optionLabels[value] || value}</option>`,
      )
      .join("");
    select.value = this.selectedProtocol;
  }

  /**
   * Select a credential type and update the UI accordingly.
   * - Restricts available protocols to those valid for the credential type
   * - Resets protocol if the current one is invalid
   * - Updates claims, request, and profile info
   */
  private selectCredentialType(type: CredentialType): void {
    this.selectedCredentialType = type;
    this.selectedClaims.clear();

    // Update credential type button active state
    document.querySelectorAll(".credential-type-btn").forEach((btn) => {
      btn.classList.toggle(
        "active",
        (btn as HTMLElement).dataset.type === type,
      );
    });

    // Rebuild protocol options for this credential type
    this.buildProtocolOptions();
    this.updateProtocolDescription();

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
   * Update the profile information display based on selected credential type and protocol.
   * Shows protocol-specific metadata (request format, response mode, transport, URL/API)
   * instead of the static credential-type profile info, so the user sees details
   * that match the actual selected protocol.
   */
  private updateProfileInfo(): void {
    const profileContainer = document.getElementById("profile-info");
    if (!profileContainer) return;

    const config = CREDENTIAL_TYPES[this.selectedCredentialType];
    if (!config) {
      profileContainer.innerHTML = "";
      return;
    }

    const isAnnexA = config.profile === "annex-a";
    const badgeColor = isAnnexA ? "bg-green-600" : "bg-blue-600";
    const borderColor = isAnnexA ? "border-green-500/30" : "border-blue-500/30";
    const bgColor = isAnnexA ? "bg-green-950/30" : "bg-blue-950/30";

    const formatLabel =
      config?.format === "dc+sd-jwt" ? "SD-JWT VC" : "MSO MDOC";
    const formatBadgeColor =
      config?.format === "dc+sd-jwt" ? "bg-amber-600" : "bg-slate-600";

    // Get protocol-specific info
    const protocolInfo = RelyingPartyApp.PROTOCOL_INFO[this.selectedProtocol];
    const protocolLabel = this.getProtocolLabel(this.selectedProtocol);

    // Determine if this is a W3C DC API based protocol (Annex C)
    const isAnnexC = [
      "w3c-dc-openid4vp",
      "w3c-dc-iso-mdoc",
      "w3c-dc-fallback",
    ].includes(this.selectedProtocol);
    const transportBadgeColor = isAnnexC ? "bg-purple-600" : "bg-indigo-600";

    profileContainer.innerHTML = `
      <div class="rounded-lg ${bgColor} ${borderColor} border p-4 mb-6">
        <div class="mb-3">
          <div class="flex items-center gap-2 mb-1.5 flex-wrap">
            <span class="px-2 py-1 ${badgeColor} text-xs font-semibold rounded-full whitespace-nowrap">${config.name}</span>
            <span class="px-2 py-1 ${formatBadgeColor} text-xs font-semibold rounded-full whitespace-nowrap">${formatLabel}</span>
            <span class="px-2 py-1 ${transportBadgeColor} text-xs font-semibold rounded-full whitespace-nowrap">${protocolLabel}</span>
          </div>
          <p class="text-gray-400 text-sm">${protocolInfo?.transport || ""}</p>
        </div>
        <div class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span class="text-gray-500">Request Format:</span>
            <span class="ml-2 text-white font-mono text-xs leading-relaxed">${protocolInfo?.requestFormat || "—"}</span>
          </div>
          <div>
            <span class="text-gray-500">Response Mode:</span>
            <span class="ml-2 text-white font-mono text-xs leading-relaxed">${protocolInfo?.responseMode || "—"}</span>
          </div>
          <div class="col-span-2">
            <span class="text-gray-500">URL Scheme / API:</span>
            <span class="ml-2 text-white font-mono text-xs leading-relaxed">${protocolInfo?.urlScheme || "—"}</span>
          </div>
        </div>
      </div>
    `;
  }

  /**
   * Show or hide the x509_san_dns checkbox based on the selected protocol.
   */
  private updateX509SanDnsVisibility(): void {
    const label = document.getElementById("x509-san-dns-label");
    if (!label) return;
    // Only show for OpenID4VP protocols, and never for Proof of Age (Annex A)
    const isOpenId4Vp =
      this.selectedProtocol === "openid4vp-same-device" ||
      this.selectedProtocol === "openid4vp-cross-device";
    const isProofOfAge = this.selectedCredentialType === "proof-of-age";
    label.classList.toggle("hidden", !isOpenId4Vp || isProofOfAge);
  }

  /**
   * Return a short human-readable label for a protocol value.
   */
  private getProtocolLabel(protocol: string): string {
    const labels: Record<string, string> = {
      "w3c-dc-openid4vp": "Annex C / OpenID4VP over DC API",
      "w3c-dc-iso-mdoc": "Annex C / ISO mDoc over DC API",
      "w3c-dc-fallback": "Annex C / Fallback",
      "openid4vp-cross-device": "OpenID4VP Cross-Device",
      "openid4vp-same-device": "OpenID4VP Same-Device",
    };
    return labels[protocol] || "Unknown Protocol";
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
      // For HAIP with x509_hash scheme, the wallet validates the client_id by
      // computing the SHA-256 hash of the leaf certificate from the JAR's x5c
      // header and comparing it to the hash in client_id.  No DNS SAN hostname
      // constraint is required (unlike x509_san_dns).
      //
      // For x509_dns_san, we use demo.ewqwe.local
      // as the public URL hostname for consistency with TLS certificate SANs.
      //
      //For Annex A (redirect_uri scheme) there is no such constraint, so we
      // can use the document origin directly.

      // const profile = getProfileForType(this.selectedCredentialType);
      // let publicUrl: string;
      // if (profile?.id === "haip") {
      //   const u = new URL(globalThis.location.href);
      //   u.hostname = "demo.ewqwe.local";
      //   publicUrl = u.origin;
      // } else {
      //   publicUrl = globalThis.location.origin;
      // }

      const profile: ProfileId | undefined =
        this.useX509SanDns &&
        (this.selectedProtocol === "openid4vp-same-device" ||
          this.selectedProtocol === "openid4vp-cross-device")
          ? "haip-x509-san-dns"
          : undefined;

      const request = buildInitTransactionRequest(
        globalThis.location.origin,
        this.selectedCredentialType,
        Array.from(this.selectedClaims),
        profile,
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
        supported: "DigitalCredential" in globalThis, // typeof globalThis.DigitalCredential !== "undefined",
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
        this.selectedProtocol,
      );
      this.logger.log("Backend verification result", {
        success: verificationResult.success,
        message: verificationResult.message,
      });

      // Display the result
      await this.displayVerificationResult(verificationResult, response);
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
  private async displayVerificationResult(
    result: VerifyResponse,
    response: OpenID4VPResponse,
  ): Promise<void> {
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
      let warningHtml = "";
      let statusClass = "result-success";
      let statusIcon = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />`;
      let statusText = "Verification Successful";

      let attestationClaims: Record<string, unknown>;
      let expiryStatus: "valid" | "expired" | "not_yet_valid" = "valid";

      try {
        attestationClaims = await parseAttestation(
          result.attestation,
          "/ewqwe_api/openid4vp/.well-known/jwks.json",
        );
        this.logger.log(
          "Parsed and verified attestation claims",
          attestationClaims,
        );
      } catch (error) {
        if (
          error instanceof Error &&
          error.message.includes("Attestation JWT is expired")
        ) {
          expiryStatus = "expired";
          statusClass = "result-warning";
          statusText = "Verification Successful (Expired)";
          statusIcon = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />`;
          this.logger.log(
            "Attestation is expired, decoding claims for display",
          );
          attestationClaims = decodeAttestation(result.attestation);
        } else if (
          error instanceof Error &&
          error.message.includes("Attestation JWT is not yet valid")
        ) {
          expiryStatus = "not_yet_valid";
          statusClass = "result-warning";
          statusText = "Verification Successful (Not Yet Valid)";
          statusIcon = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />`;
          this.logger.log(
            "Attestation is not yet valid, decoding claims for display",
          );
          attestationClaims = decodeAttestation(result.attestation);
        } else {
          this.logger.error("Failed to parse attestation", error);
          this.displayError("Invalid attestation token");
          return;
        }
      }

      const reservedKeys = new Set([
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "verified",
        "nonce",
        "doc_type",
        "namespace",
      ]);
      const credentialEntries = Object.entries(attestationClaims).filter(
        ([key]) => !reservedKeys.has(key),
      );
      const claimsHtml =
        credentialEntries.length > 0
          ? credentialEntries
              .map(([key, value]) => this.renderClaimRow(key, value))
              .join("")
          : "";

      if (expiryStatus === "expired") {
        warningHtml = `
          <div class="bg-yellow-500/20 border border-yellow-500/50 rounded-lg p-4 mb-4">
            <div class="flex items-start">
              <svg class="w-5 h-5 text-yellow-400 mr-2 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div>
                <p class="text-yellow-200 font-medium">The attestation has expired and should be re-verified.</p>
                <p class="text-yellow-300 text-sm mt-1">Stored credential claims are shown for debugging purposes.</p>
              </div>
            </div>
          </div>
        `;
      } else if (expiryStatus === "not_yet_valid") {
        warningHtml = `
          <div class="bg-yellow-500/20 border border-yellow-500/50 rounded-lg p-4 mb-4">
            <div class="flex items-start">
              <svg class="w-5 h-5 text-yellow-400 mr-2 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div>
                <p class="text-yellow-200 font-medium">The attestation is not yet valid and should be re-verified later.</p>
                <p class="text-yellow-300 text-sm mt-1">Stored credential claims are shown for debugging purposes.</p>
              </div>
            </div>
          </div>
        `;
      }

      resultIcon.setAttribute(
        "class",
        `w-6 h-6 mr-3 ${
          expiryStatus === "valid" ? "text-green-400" : "text-yellow-400"
        }`,
      );
      resultIcon.innerHTML = statusIcon;
      resultTitle.textContent = statusText;
      resultTitle.setAttribute("class", statusClass);

      resultContent.innerHTML = `
        ${warningHtml}
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
    void this.displayVerificationResult(
      {
        success: false,
        message: "Request failed",
        attestation: "",
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
   * Image claim keys whose values are raw binary encoded as base64.
   */
  private static readonly IMAGE_CLAIMS = new Set([
    "portrait",
    "signature",
    "signature_usual_mark",
  ]);

  /**
   * Render a single claim row. Image claims (portrait, signature) show an <img> instead of text.
   */
  private renderClaimRow(key: string, value: unknown): string {
    const label = this.formatClaimName(key);
    if (
      RelyingPartyApp.IMAGE_CLAIMS.has(key) &&
      typeof value === "string" &&
      value.length > 0
    ) {
      // The portrait value from the mDoc credential is base64url-encoded
      // (CBOR byte strings use URL-safe base64). Convert to standard base64
      // for the data: URI, which does not understand base64url characters.
      const standardBase64 = value.replace(/-/g, "+").replace(/_/g, "/");
      const mimeType = RelyingPartyApp.detectImageMimeType(standardBase64);
      const src = `data:${mimeType};base64,${standardBase64}`;
      // JPEG 2000 is not renderable in browsers; show a placeholder note
      const altAttr = `${label}${mimeType === "image/jp2" ? " (JPEG 2000 — may not display)" : ""}`;
      return `
        <div class="flex justify-between items-center py-2 border-b border-white/10">
          <span class="text-gray-400">${label}</span>
          <img src="${src}" alt="${altAttr}" class="h-20 w-16 object-cover rounded" />
        </div>
      `;
    }
    return `
      <div class="flex justify-between items-center py-2 border-b border-white/10">
        <span class="text-gray-400">${label}</span>
        <span class="font-medium">${this.formatClaimValue(value)}</span>
      </div>
    `;
  }

  /**
   * Detect image MIME type from magic bytes encoded in standard base64.
   * Adds missing `=` padding before decoding.
   */
  private static detectImageMimeType(base64Std: string): string {
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

      // PNG signature \x89PNG\r\n\x1a\n
      if (
        bytes[0] === 0x89 &&
        bytes[1] === 0x50 &&
        bytes[2] === 0x4e &&
        bytes[3] === 0x47
      ) {
        return "image/png";
      }

      // GIF87a or GIF89a
      if (
        bytes[0] === 0x47 &&
        bytes[1] === 0x49 &&
        bytes[2] === 0x46 &&
        bytes[3] === 0x38 &&
        (bytes[4] === 0x37 || bytes[4] === 0x39) &&
        bytes[5] === 0x61
      ) {
        return "image/gif";
      }

      // WebP: RIFF....WEBP (12-byte signature)
      if (
        bytes[0] === 0x52 &&
        bytes[1] === 0x49 &&
        bytes[2] === 0x46 &&
        bytes[3] === 0x46 &&
        bytes[8] === 0x57 &&
        bytes[9] === 0x45 &&
        bytes[10] === 0x42 &&
        bytes[11] === 0x50
      ) {
        return "image/webp";
      }

      // JPEG 2000 — two possible signatures:
      //   SIZ marker (\x00\x00\x00\x0cjP  ) — JP2 file format
      //   SOC marker (\xff\x4f\xff\x51) — raw J2K codestream
      if (
        (bytes[0] === 0x00 &&
          bytes[1] === 0x00 &&
          bytes[2] === 0x00 &&
          bytes[3] === 0x0c &&
          bytes[4] === 0x6a &&
          bytes[5] === 0x50 &&
          bytes[6] === 0x20 &&
          bytes[7] === 0x20) ||
        (bytes[0] === 0xff &&
          bytes[1] === 0x4f &&
          bytes[2] === 0xff &&
          bytes[3] === 0x51)
      ) {
        return "image/jp2";
      }

      // Default fallback — assume JPEG
      return "image/jpeg";
    } catch {
      // If decoding fails for any reason, fall back to JPEG
      return "image/jpeg";
    }
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

  private resetUI(): void {
    sessionStorage.removeItem("verificationResult");
    document.getElementById("verification-result")?.classList.add("hidden");
    document.getElementById("debug-result")?.classList.add("hidden");
    this.currentResponse = null;
    globalThis.scrollTo({ top: 0, behavior: "smooth" });
  }
}
