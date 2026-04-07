import type { CredentialStore } from "./store.ts";
import type { DebugLogger } from "./debug.ts";
import type { StoredCredential, OpenID4VPRequest, OpenID4VPResponse, PresentationSubmission } from "./types.ts";

/**
 * Wallet Application - Main controller for the digital wallet
 */
export class WalletApp {
  private store: CredentialStore;
  private logger: DebugLogger;

  constructor(store: CredentialStore, logger: DebugLogger) {
    this.store = store;
    this.logger = logger;
  }

  initialize(): void {
    this.setupEventListeners();
    this.checkAPISupport();
    this.renderCredentials();
    this.updatePresentButton();
  }

  private setupEventListeners(): void {
    // Add credential button
    document.getElementById("add-credential-btn")?.addEventListener("click", () => {
      this.showModal("add-credential-modal");
    });

    // Get credential from AP button
    document.getElementById("get-credential-btn")?.addEventListener("click", () => {
      this.showModal("add-credential-modal");
    });

    // Present credential button
    document.getElementById("present-credential-btn")?.addEventListener("click", () => {
      this.startPresentation();
    });

    // Cancel add credential
    document.getElementById("cancel-add-credential")?.addEventListener("click", () => {
      this.hideModal("add-credential-modal");
    });

    // Cancel present
    document.getElementById("cancel-present")?.addEventListener("click", () => {
      this.hideModal("present-credential-modal");
    });

    // Confirm present
    document.getElementById("confirm-present")?.addEventListener("click", () => {
      this.confirmPresentation();
    });

    // AP options
    document.querySelectorAll(".ap-option").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const target = e.currentTarget as HTMLElement;
        const apType = target.dataset.ap;
        this.getCredentialFromAP(apType as "gov-id" | "edu" | "employment");
      });
    });

    // Toggle debug panel
    document.getElementById("toggle-debug")?.addEventListener("click", () => {
      const content = document.getElementById("debug-content");
      content?.classList.toggle("hidden");
    });

    // Modal backdrop clicks
    ["add-credential-modal", "present-credential-modal"].forEach((modalId) => {
      document.getElementById(modalId)?.addEventListener("click", (e) => {
        if (e.target === e.currentTarget) {
          this.hideModal(modalId);
        }
      });
    });
  }

  private checkAPISupport(): void {
    const statusEl = document.getElementById("api-status");
    if (!statusEl) return;

    const checks = [
      {
        name: "Digital Credentials API",
        supported: typeof (globalThis as unknown as { DigitalCredential?: unknown }).DigitalCredential !== "undefined",
      },
      {
        name: "Credential Management",
        supported: "credentials" in navigator,
      },
      {
        name: "Secure Context",
        supported: window.isSecureContext,
      },
      {
        name: "Local Storage",
        supported: typeof localStorage !== "undefined",
      },
      {
        name: "Crypto API",
        supported: typeof crypto !== "undefined" && typeof crypto.randomUUID === "function",
      },
    ];

    statusEl.innerHTML = checks
      .map(
        (check) => `
        <div class="flex items-center justify-between">
          <span class="text-gray-600">${check.name}</span>
          <span class="${check.supported ? "text-green-600" : "text-amber-600"}">
            ${check.supported ? "✓" : "⚠"}
          </span>
        </div>
      `
      )
      .join("");

    this.logger.log("API support checked", checks);
  }

  private renderCredentials(): void {
    const listEl = document.getElementById("credentials-list");
    const emptyEl = document.getElementById("empty-state");
    if (!listEl || !emptyEl) return;

    const credentials = this.store.getAll();

    if (credentials.length === 0) {
      listEl.innerHTML = "";
      emptyEl.classList.remove("hidden");
      return;
    }

    emptyEl.classList.add("hidden");
    listEl.innerHTML = credentials
      .map((cred) => this.renderCredentialCard(cred))
      .join("");

    // Add delete event listeners
    listEl.querySelectorAll(".delete-credential").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const target = e.currentTarget as HTMLElement;
        const credId = target.dataset.id;
        if (credId) {
          this.deleteCredential(credId);
        }
      });
    });

    // Add view details event listeners
    listEl.querySelectorAll(".view-credential").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const target = e.currentTarget as HTMLElement;
        const credId = target.dataset.id;
        if (credId) {
          this.viewCredentialDetails(credId);
        }
      });
    });
  }

  private renderCredentialCard(cred: StoredCredential): string {
    const typeClass = cred.type === "mdl" ? "mdl" : 
                      cred.type === "national-id" ? "national-id" :
                      cred.type === "education" ? "education" : "employment";
    
    const expiryDate = cred.expiresAt 
      ? new Date(cred.expiresAt).toLocaleDateString() 
      : "No expiry";

    return `
      <div class="credential-card ${typeClass} animate-fade-in">
        <div class="flex justify-between items-start mb-4">
          <div>
            <h3 class="text-lg font-semibold">${cred.displayName}</h3>
            <p class="text-sm opacity-80">${cred.issuer}</p>
          </div>
          <div class="flex space-x-2">
            <button class="view-credential p-2 hover:bg-white/20 rounded-lg transition-colors" data-id="${cred.id}" title="View Details">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              </svg>
            </button>
            <button class="delete-credential p-2 hover:bg-white/20 rounded-lg transition-colors" data-id="${cred.id}" title="Delete">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
          </div>
        </div>
        <div class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span class="opacity-70">Issued:</span>
            <span class="ml-2">${new Date(cred.issuedAt).toLocaleDateString()}</span>
          </div>
          <div>
            <span class="opacity-70">Expires:</span>
            <span class="ml-2">${expiryDate}</span>
          </div>
        </div>
        <div class="mt-4 pt-4 border-t border-white/20">
          <div class="text-xs opacity-70 font-mono truncate">ID: ${cred.id}</div>
        </div>
      </div>
    `;
  }

  private getCredentialFromAP(type: "gov-id" | "edu" | "employment"): void {
    this.hideModal("add-credential-modal");
    
    const credentialType = type === "gov-id" ? "mdl" : 
                          type === "edu" ? "education" : "employment";
    
    this.logger.log(`Requesting credential from AP: ${type}`);
    
    // Simulate AP authentication flow
    setTimeout(() => {
      const credential = this.store.generateDemoCredential(credentialType);
      this.store.add(credential);
      this.renderCredentials();
      this.updatePresentButton();
      this.logger.success(`Credential obtained from ${type} provider`, credential);
    }, 1000);
  }

  private deleteCredential(id: string): void {
    if (confirm("Are you sure you want to delete this credential?")) {
      this.store.remove(id);
      this.renderCredentials();
      this.updatePresentButton();
    }
  }

  private viewCredentialDetails(id: string): void {
    const credential = this.store.get(id);
    if (credential) {
      this.logger.log(`Credential details: ${credential.displayName}`, credential);
      
      // Show debug panel if hidden
      const debugContent = document.getElementById("debug-content");
      debugContent?.classList.remove("hidden");
    }
  }

  private updatePresentButton(): void {
    const btn = document.getElementById("present-credential-btn") as HTMLButtonElement;
    if (btn) {
      btn.disabled = this.store.getAll().length === 0;
    }
  }

  private startPresentation(): void {
    const credentials = this.store.getAll();
    if (credentials.length === 0) {
      this.logger.error("No credentials available for presentation");
      return;
    }

    // Create a demo presentation request
    const request: OpenID4VPRequest = {
      client_id: "https://demo.relying-party.example",
      response_type: "vp_token",
      nonce: crypto.randomUUID(),
      presentation_definition: {
        id: crypto.randomUUID(),
        input_descriptors: [
          {
            id: "identity_credential",
            name: "Identity Verification",
            purpose: "We need to verify your identity",
            constraints: {
              fields: [
                { path: ["$.credentialSubject.familyName"] },
                { path: ["$.credentialSubject.givenName"] },
              ],
            },
          },
        ],
      },
    };

    this.renderPresentationModal(request, credentials);
    this.showModal("present-credential-modal");
  }

  private renderPresentationModal(request: OpenID4VPRequest, credentials: StoredCredential[]): void {
    const requestEl = document.getElementById("presentation-request");
    const selectionEl = document.getElementById("credential-selection");

    if (requestEl) {
      requestEl.innerHTML = `
        <div class="bg-amber-50 border border-amber-200 rounded-lg p-4 mb-4">
          <div class="flex items-center">
            <svg class="w-5 h-5 text-amber-600 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span class="font-medium text-amber-800">Presentation Request</span>
          </div>
        </div>
        <div class="space-y-3 text-sm">
          <div class="flex justify-between">
            <span class="text-gray-500">Relying Party:</span>
            <span class="font-medium">${request.client_id}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-500">Purpose:</span>
            <span class="font-medium">${request.presentation_definition.input_descriptors[0]?.purpose || "Identity verification"}</span>
          </div>
          <div>
            <span class="text-gray-500">Requested Claims:</span>
            <ul class="mt-1 list-disc list-inside text-gray-700">
              ${request.presentation_definition.input_descriptors[0]?.constraints?.fields?.map(
                (f) => `<li>${f.path[0].replace("$.credentialSubject.", "")}</li>`
              ).join("") || ""}
            </ul>
          </div>
        </div>
      `;
    }

    if (selectionEl) {
      selectionEl.innerHTML = `
        <p class="text-sm text-gray-500 mb-3">Select a credential to present:</p>
        ${credentials.map((cred, index) => `
          <label class="flex items-center p-3 border rounded-lg cursor-pointer hover:bg-gray-50 transition-colors ${index === 0 ? "border-indigo-500 bg-indigo-50" : "border-gray-200"}">
            <input type="radio" name="credential" value="${cred.id}" class="form-radio text-indigo-600" ${index === 0 ? "checked" : ""}>
            <div class="ml-3">
              <div class="font-medium text-gray-900">${cred.displayName}</div>
              <div class="text-sm text-gray-500">${cred.issuer}</div>
            </div>
          </label>
        `).join("")}
      `;
    }

    this.logger.log("Presentation request received", request);
  }

  private confirmPresentation(): void {
    const selectedRadio = document.querySelector('input[name="credential"]:checked') as HTMLInputElement;
    if (!selectedRadio) {
      this.logger.error("No credential selected");
      return;
    }

    const credential = this.store.get(selectedRadio.value);
    if (!credential) {
      this.logger.error("Selected credential not found");
      return;
    }

    // Create presentation response
    const response: OpenID4VPResponse = {
      vp_token: btoa(JSON.stringify(credential.credential)),
      presentation_submission: {
        id: crypto.randomUUID(),
        definition_id: crypto.randomUUID(),
        descriptor_map: [
          {
            id: "identity_credential",
            format: "jwt_vp",
            path: "$",
          },
        ],
      },
    };

    this.logger.success("Credential presentation authorized", {
      credential: credential.displayName,
      response,
    });

    this.hideModal("present-credential-modal");
    
    // In a real implementation, this would send the response to the RP
    alert(`Credential "${credential.displayName}" has been presented successfully!`);
  }

  private showModal(id: string): void {
    document.getElementById(id)?.classList.remove("hidden");
  }

  private hideModal(id: string): void {
    document.getElementById(id)?.classList.add("hidden");
  }
}
