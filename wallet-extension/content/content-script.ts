/**
 * EU Age Verification Wallet - Content Script
 *
 * Injected into web pages to:
 * - Detect Digital Credentials API requests
 * - Intercept OpenID4VP requests via av:// protocol
 * - Communicate with the extension background worker
 */

/// <reference path="../src/browser.d.ts" />

// Cross-browser runtime API
const runtime =
  typeof browser !== "undefined" ? browser.runtime : chrome.runtime;

console.log("[EU AV Wallet] Content script loaded");

/**
 * Check if the page is requesting digital credentials
 * and intercept if our wallet can handle it
 */
function setupDigitalCredentialsInterception() {
  // Store original navigator.credentials.get
  const originalGet = navigator.credentials?.get?.bind(navigator.credentials);

  if (!originalGet) {
    console.log("[EU AV Wallet] Credential Management API not available");
    return;
  }

  // Check if Digital Credentials API is available
  if (
    typeof (globalThis as unknown as { DigitalCredential?: unknown })
      .DigitalCredential === "undefined"
  ) {
    console.log(
      "[EU AV Wallet] Digital Credentials API not natively supported - extension will handle",
    );
  }

  // We don't override navigator.credentials.get directly as that would conflict
  // with the browser's built-in handling. Instead, we listen for specific events
  // or custom URL schemes.
}

/**
 * Handle av:// protocol links for OpenID4VP fallback
 * Per EU AV Profile: "As a way to invoke the AVI, at least a custom URL scheme av:// MUST be supported"
 */
function setupProtocolHandler() {
  console.log(
    "[EU AV Wallet] Setting up protocol handler and message listener",
  );

  // Listen for clicks on av:// links
  document.addEventListener(
    "click",
    (event) => {
      const target = event.target as HTMLElement;
      const link = target.closest("a");

      if (link?.href?.startsWith("av://")) {
        event.preventDefault();
        handleAVProtocol(link.href);
      }
    },
    true,
  );

  // Listen for custom events from the page
  window.addEventListener("message", (event) => {
    // Log all messages for debugging
    if (event.data?.type?.startsWith("EU_AV")) {
      console.log(
        "[EU AV Wallet] Received message:",
        event.data.type,
        event.data,
      );
    }

    if (event.source !== window) return;

    if (event.data?.type === "EU_AV_WALLET_REQUEST") {
      handleWalletRequest(event.data.payload, event.data.requestId);
    }
  });
}

/**
 * Handle av:// protocol URLs
 * Format: av://?credential_offer=... or av://?request_uri=...
 */
async function handleAVProtocol(url: string) {
  console.log("[EU AV Wallet] Handling av:// protocol:", url);

  try {
    const avUrl = new URL(url.replace("av://", "https://av.local/"));
    const credentialOffer = avUrl.searchParams.get("credential_offer");
    const requestUri = avUrl.searchParams.get("request_uri");

    if (credentialOffer) {
      // This is an issuance request - not implemented in this version
      console.log(
        "[EU AV Wallet] Credential offer received (issuance not yet implemented)",
      );
      showNotification(
        "Credential issuance is not yet supported in this wallet version.",
      );
      return;
    }

    if (requestUri) {
      // This is a presentation request
      await handlePresentationRequestUri(requestUri);
    }
  } catch (error) {
    console.error("[EU AV Wallet] Failed to handle av:// protocol:", error);
  }
}

/**
 * Handle presentation request URI
 */
async function handlePresentationRequestUri(requestUri: string) {
  try {
    // Fetch the authorization request
    const response = await fetch(requestUri);
    const params = new URLSearchParams(await response.text());

    const request = {
      response_type: params.get("response_type"),
      response_mode: params.get("response_mode"),
      client_id: params.get("client_id"),
      response_uri: params.get("response_uri"),
      nonce: params.get("nonce"),
      state: params.get("state"),
      dcql_query: params.get("dcql_query")
        ? JSON.parse(params.get("dcql_query")!)
        : null,
    };

    // Send to background for processing
    const result = await runtime.sendMessage({
      type: "PRESENT_CREDENTIAL",
      request,
    });

    console.log("[EU AV Wallet] Presentation result:", result);
  } catch (error) {
    console.error(
      "[EU AV Wallet] Failed to handle presentation request:",
      error,
    );
  }
}

/**
 * Handle wallet request from page
 */
async function handleWalletRequest(payload: unknown, requestId?: string) {
  console.log(
    "[EU AV Wallet] Wallet request received:",
    payload,
    "requestId:",
    requestId,
  );

  try {
    // Forward to background worker to get matching credentials
    const response = await runtime.sendMessage({
      type: "DC_API_REQUEST",
      request: payload,
    });

    console.log("[EU AV Wallet] Background response:", response);

    if (response.error) {
      sendResponseToPage(requestId, { error: response.error });
      return;
    }

    const matchingCredentials = response.matchingCredentials || [];

    if (matchingCredentials.length === 0) {
      showNotification("No matching credentials found in your wallet");
      sendResponseToPage(requestId, { response: null });
      return;
    }

    // Show credential selection UI
    const selectedCredential = await showCredentialSelector(
      matchingCredentials,
      payload,
    );

    if (!selectedCredential) {
      sendResponseToPage(requestId, { cancelled: true });
      return;
    }

    // Build the response in OpenID4VP format
    const vpResponse = buildVPResponse(selectedCredential, payload);
    sendResponseToPage(requestId, { response: vpResponse });
  } catch (error) {
    console.error("[EU AV Wallet] Error handling wallet request:", error);
    sendResponseToPage(requestId, { error: String(error) });
  }
}

/**
 * Send response back to the requesting page
 */
function sendResponseToPage(requestId: string | undefined, payload: unknown) {
  window.postMessage(
    {
      type: "EU_AV_WALLET_RESPONSE",
      requestId,
      payload,
    },
    "*",
  );
}

/**
 * Build an OpenID4VP response from the selected credential
 */
function buildVPResponse(credential: StoredCredential, request: unknown) {
  const nonce =
    (request as { data?: { nonce?: string } })?.data?.nonce ||
    crypto.randomUUID();

  // Build VP token with the credential claims
  const vpToken = {
    docType: credential.docType,
    namespace: credential.namespace,
    claims: credential.claims,
    issuer: credential.issuer,
    issuedAt: credential.issuedAt,
    expiresAt: credential.expiresAt,
  };

  return {
    vp_token: JSON.stringify(vpToken),
    presentation_submission: {
      id: crypto.randomUUID(),
      definition_id: "credential_presentation",
      descriptor_map: [
        {
          id: credential.type + "_credential",
          format: "mso_mdoc",
          path: "$",
        },
      ],
    },
    state: (request as { data?: { state?: string } })?.data?.state,
    nonce,
  };
}

interface StoredCredential {
  id: string;
  type: string;
  docType: string;
  namespace: string;
  displayName: string;
  issuer: string;
  issuedAt: string;
  expiresAt: string;
  claims: Record<string, unknown>;
}

/**
 * Show a credential selection UI overlay
 */
function showCredentialSelector(
  credentials: StoredCredential[],
  _request: unknown,
): Promise<StoredCredential | null> {
  return new Promise((resolve) => {
    // Create overlay
    const overlay = document.createElement("div");
    overlay.id = "eu-av-wallet-overlay";
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 999999;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    // Create modal
    const modal = document.createElement("div");
    modal.style.cssText = `
      background: linear-gradient(135deg, #1e1b4b 0%, #581c87 50%, #1e1b4b 100%);
      border-radius: 16px;
      padding: 24px;
      max-width: 400px;
      width: 90%;
      max-height: 80vh;
      overflow-y: auto;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      border: 1px solid rgba(168, 85, 247, 0.3);
    `;

    // Header
    const header = document.createElement("div");
    header.style.cssText = `
      display: flex;
      align-items: center;
      margin-bottom: 20px;
      padding-bottom: 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    `;
    header.innerHTML = `
      <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #6366f1, #7c3aed); border-radius: 10px; display: flex; align-items: center; justify-content: center; margin-right: 12px;">
        <svg width="20" height="20" fill="none" stroke="white" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      </div>
      <div>
        <h2 style="margin: 0; font-size: 18px; font-weight: 600; color: white;">EU AV Wallet</h2>
        <p style="margin: 4px 0 0; font-size: 12px; color: rgba(255,255,255,0.6);">Select a credential to share</p>
      </div>
    `;
    modal.appendChild(header);

    // Site info
    const siteInfo = document.createElement("div");
    siteInfo.style.cssText = `
      background: rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 16px;
      font-size: 13px;
      color: rgba(255, 255, 255, 0.8);
    `;
    siteInfo.innerHTML = `
      <div style="color: rgba(255,255,255,0.5); font-size: 11px; margin-bottom: 4px;">Requesting site:</div>
      <div style="font-weight: 500;">${window.location.origin}</div>
    `;
    modal.appendChild(siteInfo);

    // Credentials list
    const list = document.createElement("div");
    list.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 10px;
      margin-bottom: 16px;
    `;

    credentials.forEach((cred) => {
      const card = document.createElement("button");
      card.style.cssText = `
        background: rgba(255, 255, 255, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 12px;
        padding: 14px;
        cursor: pointer;
        text-align: left;
        transition: all 0.2s;
        display: flex;
        align-items: center;
        gap: 12px;
      `;

      const iconColor =
        {
          mdl: "#60a5fa",
          "national-id": "#34d399",
          "proof-of-age": "#a78bfa",
        }[cred.type] || "#818cf8";

      card.innerHTML = `
        <div style="width: 40px; height: 40px; background: ${iconColor}33; border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
          <svg width="20" height="20" fill="none" stroke="${iconColor}" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div style="flex: 1; min-width: 0;">
          <div style="font-weight: 500; color: white; font-size: 14px;">${cred.displayName}</div>
          <div style="font-size: 12px; color: rgba(255,255,255,0.5); margin-top: 2px;">${cred.issuer}</div>
        </div>
        <svg width="20" height="20" fill="none" stroke="rgba(255,255,255,0.4)" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
        </svg>
      `;

      card.addEventListener("mouseenter", () => {
        card.style.background = "rgba(255, 255, 255, 0.15)";
        card.style.borderColor = "rgba(168, 85, 247, 0.5)";
      });
      card.addEventListener("mouseleave", () => {
        card.style.background = "rgba(255, 255, 255, 0.1)";
        card.style.borderColor = "rgba(255, 255, 255, 0.2)";
      });
      card.addEventListener("click", () => {
        overlay.remove();
        resolve(cred);
      });

      list.appendChild(card);
    });

    modal.appendChild(list);

    // Cancel button
    const cancelBtn = document.createElement("button");
    cancelBtn.textContent = "Cancel";
    cancelBtn.style.cssText = `
      width: 100%;
      padding: 12px;
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 8px;
      color: white;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.2s;
    `;
    cancelBtn.addEventListener("mouseenter", () => {
      cancelBtn.style.background = "rgba(255, 255, 255, 0.15)";
    });
    cancelBtn.addEventListener("mouseleave", () => {
      cancelBtn.style.background = "rgba(255, 255, 255, 0.1)";
    });
    cancelBtn.addEventListener("click", () => {
      overlay.remove();
      resolve(null);
    });
    modal.appendChild(cancelBtn);

    // Close on overlay click
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) {
        overlay.remove();
        resolve(null);
      }
    });

    overlay.appendChild(modal);
    document.body.appendChild(overlay);
  });
}

/**
 * Show a notification to the user
 */
function showNotification(message: string) {
  // Create a simple toast notification
  const toast = document.createElement("div");
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 12px 20px;
    background: #7c3aed;
    color: white;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    z-index: 999999;
    animation: slideIn 0.3s ease;
  `;
  toast.textContent = message;

  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = "slideOut 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

/**
 * Inject CSS for animations
 */
function injectStyles() {
  const style = document.createElement("style");
  style.textContent = `
    @keyframes slideIn {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
      from { transform: translateX(0); opacity: 1; }
      to { transform: translateX(100%); opacity: 0; }
    }
  `;

  // Wait for head to be available (script runs at document_start)
  if (document.head) {
    document.head.appendChild(style);
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      document.head.appendChild(style);
    });
  }
}

// Initialize when DOM is ready
function initialize() {
  console.log("[EU AV Wallet] Initializing content script handlers");
  injectStyles();
  setupDigitalCredentialsInterception();
  setupProtocolHandler();
}

// Run immediately for message handling, defer DOM operations
setupProtocolHandler();
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    injectStyles();
    setupDigitalCredentialsInterception();
  });
} else {
  injectStyles();
  setupDigitalCredentialsInterception();
}
