/**
 * EU Age Verification Wallet - Content Script
 *
 * Injected into web pages to:
 * - Detect Digital Credentials API requests
 * - Intercept OpenID4VP requests via av:// protocol
 * - Communicate with the extension background worker
 */

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
    if (event.data?.type === "EU_AV_WALLET_REQUEST") {
      handleWalletRequest(event.data.payload);
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
async function handleWalletRequest(payload: unknown) {
  console.log("[EU AV Wallet] Wallet request received:", payload);

  // Forward to background worker
  const response = await runtime.sendMessage({
    type: "DC_API_REQUEST",
    request: payload,
  });

  // Send response back to page
  window.postMessage(
    {
      type: "EU_AV_WALLET_RESPONSE",
      payload: response,
    },
    "*",
  );
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
  document.head.appendChild(style);
}

// Initialize
injectStyles();
setupDigitalCredentialsInterception();
setupProtocolHandler();
