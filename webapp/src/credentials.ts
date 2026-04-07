import type {
  InitTransactionRequest,
  OpenID4VPRequest,
  OpenID4VPResponse,
  PresentationSubmission,
  VerifyResponse,
} from "@ewqwe/digital-identity";
import type { DebugLogger } from "./debug.ts";

/**
 * Detect whether the browser is running on a mobile device (Android or iOS).
 */
function isMobileDevice(): boolean {
  const ua = navigator.userAgent || "";
  return /android/i.test(ua) || /iphone|ipad|ipod/i.test(ua);
}

function uuidv4(): string {
  if (
    typeof crypto !== "undefined" &&
    typeof crypto.randomUUID === "function"
  ) {
    return crypto.randomUUID();
  }
  console.error("crypto.randomUUID is not supported in this environment");
  throw new Error("crypto.randomUUID is not supported in this environment");
}

/**
 * Safely parse a presentation_submission that may arrive as a JSON string
 * (wallet form-post) or already as an object from an earlier JSON.parse.
 * Never throws — returns null if unparseable.
 */
function parsePresentationSubmission(
  value: unknown,
): PresentationSubmission | null {
  if (!value) return null;
  if (typeof value === "object") return value as PresentationSubmission;
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as PresentationSubmission;
    } catch {
      console.warn("Failed to parse presentation_submission:", value);
      return null;
    }
  }
  return null;
}

/**
 * Request credentials using the specified protocol
 * @param request The OpenID4VP request
 * @param protocol The protocol to use
 * @param logger Debug logger
 */
export async function requestCredentials(
  request: InitTransactionRequest,
  protocol: string,
  logger: DebugLogger,
): Promise<OpenID4VPResponse | null> {
  logger.log(`Requesting credentials using protocol: ${protocol}`);

  switch (protocol) {
    case "w3c-dc-fallback":
      return await requestWithFallback(request, logger);

    case "w3c-dc":
      return await requestViaW3CDC(request, logger);

    case "openid4vp-cross-device":
      // Cross-device flow with QR code (compatible with EUDI Wallet)
      return await requestViaOpenID4VPCrossDevice(request, logger);

    case "openid4vp-same-device":
      // Same-device flow with deep link (for mobile browsers)
      return await requestViaOpenID4VPSameDevice(request, logger);

    case "simulated":
      logger.log("Using simulated credential flow");
      return simulateCredentialResponse(request, logger);

    default:
      throw new Error(`Unknown protocol: ${protocol}`);
  }
}

/**
 * W3C Digital Credentials with fallback to OpenID4VP
 */
async function requestWithFallback(
  request: InitTransactionRequest,
  logger: DebugLogger,
): Promise<OpenID4VPResponse | null> {
  // Try W3C DC API first
  try {
    const response = await requestViaW3CDC(request, logger);
    if (response) {
      return response;
    }
  } catch (error) {
    logger.log("W3C DC failed, trying OpenID4VP fallback", error);
  }

  // Fall back to OpenID4VP:
  //  - same-device on Android/iOS (deep link)
  //  - cross-device (QR code) on desktop
  if (isMobileDevice()) {
    logger.log(
      "Mobile device detected — falling back to OpenID4VP same-device",
    );
    return await requestViaOpenID4VPSameDevice(request, logger);
  }
  logger.log("Desktop detected — falling back to OpenID4VP cross-device (QR)");
  return await requestViaOpenID4VPCrossDevice(request, logger);
}

/**
 * Request via W3C Digital Credentials API (native API + extension)
 */
async function requestViaW3CDC(
  request: InitTransactionRequest,
  logger: DebugLogger,
): Promise<OpenID4VPResponse | null> {
  // Build an OpenID4VP Authorization Request from the InitTransactionRequest.
  // The W3C DC API passes this directly to the wallet as the `data` field.
  const dcApiRequest: OpenID4VPRequest = {
    client_id: globalThis.location.origin,
    client_id_scheme: "redirect_uri",
    response_type: "vp_token",
    response_mode: "direct_post",
    nonce: request.nonce ?? crypto.randomUUID(),
    dcql_query: request.dcql_query,
    client_metadata: request.client_metadata,
  };

  logger.log(
    "Requesting credentials via native Digital Credentials API",
    dcApiRequest,
  );

  const credential = await navigator.credentials.get({
    digital: {
      requests: [
        {
          protocol: "openid4vp",
          data: dcApiRequest,
        },
      ],
    },
  });

  if (!credential) {
    logger.log("User cancelled the credential request");
    return null;
  }

  const digitalCredential = credential as unknown as {
    protocol: string;
    data: OpenID4VPResponse;
  };
  logger.success("Credential received via native API", digitalCredential);

  return digitalCredential.data;
}

/**
 * Request via OpenID4VP (cross-device flow with QR code)
 * Compatible with EUDI Wallet reference implementation
 *
 * Flow:
 * 1. Initialize transaction on backend (gets QR code data)
 * 2. Display QR code for user to scan with mobile wallet
 * 3. Poll for wallet response
 * 4. Return the VP token once received
 */
async function requestViaOpenID4VPCrossDevice(
  request: InitTransactionRequest,
  logger: DebugLogger,
): Promise<OpenID4VPResponse | null> {
  logger.log("OpenID4VP cross-device flow - initializing transaction");

  if (request.credential_type) {
    logger.log(`Credential type: ${request.credential_type}`);
  }

  // Step 1: Initialize the transaction on the backend
  const initResponse = await fetch("/api/openid4vp/init", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!initResponse.ok) {
    throw new Error(
      `Failed to initialize OpenID4VP transaction: ${initResponse.statusText}`,
    );
  }

  const initData = (await initResponse.json()) as {
    transaction_id: string;
    authorization_request_uri: string;
    expires_in: number;
    profile: string;
    client_id_scheme: string;
  };

  logger.log("Transaction initialized", {
    transactionId: initData.transaction_id,
    expiresIn: initData.expires_in,
    profile: initData.profile,
    clientIdScheme: initData.client_id_scheme,
  });

  // Step 2: Show QR code modal with profile info
  const qrModal = showQRCodeModal(
    initData.authorization_request_uri,
    logger,
    initData.profile,
  );

  try {
    // Step 3: Poll for wallet response
    const response = await pollForWalletResponse(
      initData.transaction_id,
      initData.expires_in * 1000,
      logger,
      qrModal.onCancel,
    );

    // Close the modal
    qrModal.close();

    if (!response) {
      logger.log("OpenID4VP request cancelled or timed out");
      return null;
    }

    logger.success("Received VP token from wallet via OpenID4VP", response);

    // Convert to OpenID4VPResponse format
    return {
      vp_token: response.vp_token,
      presentation_submission:
        parsePresentationSubmission(response.presentation_submission) ?? null,
      state: response.state,
    };
  } catch (error) {
    qrModal.close();
    throw error;
  }
}

interface QRCodeModal {
  close: () => void;
  onCancel: Promise<void>;
}

/**
 * Show a modal with QR code for the wallet to scan
 */
function showQRCodeModal(
  authorizationRequestUri: string,
  logger: DebugLogger,
  profile?: string,
): QRCodeModal {
  logger.log("Showing QR code modal", {
    uri: authorizationRequestUri.slice(0, 50) + "...",
    profile,
  });

  let cancelResolve: () => void;
  const onCancel = new Promise<void>((resolve) => {
    cancelResolve = resolve;
  });

  // Determine the wallet type based on profile
  const isHaip = profile === "haip";
  const walletName = isHaip ? "EUDI Wallet" : "Age Verification App";
  const profileBadge = isHaip
    ? '<span class="inline-block px-2 py-1 bg-blue-600 text-xs rounded-full">HAIP</span>'
    : '<span class="inline-block px-2 py-1 bg-green-600 text-xs rounded-full">Annex A</span>';

  // Create modal overlay
  const overlay = document.createElement("div");
  overlay.id = "openid4vp-qr-modal";
  overlay.className =
    "fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50";

  overlay.innerHTML = `
    <div class="bg-slate-800 rounded-2xl p-8 max-w-md w-full mx-4 border border-white/20">
      <div class="text-center">
        <div class="flex items-center justify-center gap-2 mb-2">
          <h3 class="text-xl font-semibold">Scan with your Wallet</h3>
          ${profileBadge}
        </div>
        <p class="text-gray-400 text-sm mb-6">
          Scan this QR code with your ${walletName} or compatible mobile wallet app
        </p>
        
        <div id="qr-code-container" class="bg-white p-4 rounded-xl inline-block mb-6">
          <div class="w-64 h-64 flex items-center justify-center">
            <div class="animate-spin w-8 h-8 border-4 border-indigo-500 border-t-transparent rounded-full"></div>
          </div>
        </div>
        
        <p class="text-gray-500 text-xs mb-4">
          Waiting for wallet response...
        </p>
        
        <div class="flex gap-3 justify-center">
          <button id="qr-cancel-btn" class="px-6 py-2 bg-white/10 hover:bg-white/20 rounded-lg transition-colors">
            Cancel
          </button>
          <button id="qr-copy-btn" class="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg transition-colors flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
            Copy Link
          </button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  // Generate QR code using a library or simple approach
  const qrContainer = overlay.querySelector("#qr-code-container");
  if (qrContainer) {
    // Use the QR code API service for simplicity
    // In production, use a local library like qrcode.js
    const qrImg = document.createElement("img");
    qrImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=256x256&data=${encodeURIComponent(authorizationRequestUri)}`;
    qrImg.alt = "QR Code for wallet";
    qrImg.className = "w-64 h-64";
    qrImg.onload = () => {
      qrContainer.innerHTML = "";
      qrContainer.appendChild(qrImg);
    };
    qrImg.onerror = () => {
      // Fallback: show the URI as text
      qrContainer.innerHTML = `
        <div class="w-64 h-64 flex flex-col items-center justify-center text-black text-xs p-2 overflow-hidden">
          <p class="font-medium mb-2">QR Code unavailable</p>
          <p class="break-all">${authorizationRequestUri.slice(0, 100)}...</p>
        </div>
      `;
    };
  }

  // Set up event handlers
  const cancelBtn = overlay.querySelector("#qr-cancel-btn");
  const copyBtn = overlay.querySelector("#qr-copy-btn");

  const close = () => {
    overlay.remove();
  };

  cancelBtn?.addEventListener("click", () => {
    cancelResolve();
    close();
  });

  copyBtn?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(authorizationRequestUri);
      (copyBtn as HTMLButtonElement).innerHTML = `
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
        </svg>
        Copied!
      `;
      setTimeout(() => {
        (copyBtn as HTMLButtonElement).innerHTML = `
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
          Copy Link
        `;
      }, 2000);
    } catch {
      logger.error("Failed to copy to clipboard");
    }
  });

  // Close on overlay click
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) {
      cancelResolve();
      close();
    }
  });

  return { close, onCancel };
}

interface PollResponse {
  vp_token: string;
  presentation_submission: unknown;
  state: string;
  nonce: string;
}

/**
 * Poll the backend for wallet response
 */
function pollForWalletResponse(
  transactionId: string,
  timeoutMs: number,
  logger: DebugLogger,
  onCancel: Promise<void>,
): Promise<PollResponse | null> {
  const pollInterval = 2000; // Poll every 2 seconds
  const startTime = Date.now();

  logger.log(`Polling for wallet response (timeout: ${timeoutMs / 1000}s)`);

  return new Promise((resolve) => {
    let cancelled = false;

    // Handle cancel
    onCancel.then(() => {
      cancelled = true;
      resolve(null);
    });

    const poll = async () => {
      if (cancelled) {
        return;
      }

      // Check timeout
      if (Date.now() - startTime > timeoutMs) {
        logger.log("Polling timed out");
        resolve(null);
        return;
      }

      try {
        const response = await fetch(`/api/openid4vp/status/${transactionId}`);
        const data = await response.json();

        if (data.status === "received") {
          logger.log("Wallet response received");
          resolve({
            vp_token: data.vp_token,
            presentation_submission: data.presentation_submission,
            state: data.state,
            nonce: data.nonce,
          });
          return;
        }

        if (data.status === "expired" || data.status === "error") {
          logger.error("Transaction failed", data);
          resolve(null);
          return;
        }

        // Continue polling
        if (!cancelled) {
          setTimeout(poll, pollInterval);
        }
      } catch (error) {
        logger.error("Polling error", error);
        if (!cancelled) {
          setTimeout(poll, pollInterval);
        }
      }
    };

    poll();
  });
}

/**
 * OpenID4VP Same-Device Flow
 * Uses a deep link to trigger the wallet app on the same device.
 * After wallet processes the request, it redirects back or POSTs directly.
 * This is suitable for mobile browsers where the wallet app is installed.
 */
async function requestViaOpenID4VPSameDevice(
  request: InitTransactionRequest,
  logger: DebugLogger,
): Promise<OpenID4VPResponse | null> {
  logger.log("OpenID4VP same-device flow requested");

  // Step 1: Initialize the transaction on the backend
  logger.log("Initializing OpenID4VP transaction for same-device flow...");

  if (request.credential_type) {
    logger.log(`Credential type: ${request.credential_type}`);
  }

  const initResponse = await fetch("/api/openid4vp/init", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!initResponse.ok) {
    const errorText = await initResponse.text();
    throw new Error(`Failed to initialize OpenID4VP transaction: ${errorText}`);
  }

  const initData = await initResponse.json();
  const { transaction_id, deep_link_uri } = initData;

  if (!deep_link_uri) {
    throw new Error(
      "Backend did not return a deep_link_uri for same-device flow",
    );
  }

  logger.log("Transaction initialized", { transaction_id, deep_link_uri });

  // Create a cancel promise that will be resolved when user clicks cancel
  let cancelResolve: () => void;
  const cancelPromise = new Promise<void>((resolve) => {
    cancelResolve = resolve;
  });

  // Step 2: Show instructions and open the deep link
  showSameDeviceModal(deep_link_uri, transaction_id, logger, cancelResolve!);

  // Step 3: Poll for the wallet response
  const POLL_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
  try {
    const pollResponse = await pollForWalletResponse(
      transaction_id,
      POLL_TIMEOUT_MS,
      logger,
      cancelPromise,
    );
    hideSameDeviceModal();

    if (!pollResponse) {
      return null;
    }

    // Convert PollResponse to OpenID4VPResponse
    return {
      vp_token: pollResponse.vp_token,
      presentation_submission:
        parsePresentationSubmission(pollResponse.presentation_submission) ??
        null,
      state: pollResponse.state,
    };
  } catch (error) {
    hideSameDeviceModal();
    throw error;
  }
}

/**
 * Show a modal with instructions and a button to open the wallet app
 */
function showSameDeviceModal(
  deepLinkUri: string,
  transactionId: string,
  logger: DebugLogger,
  onCancel: () => void,
): void {
  // Remove existing modal if present
  const existingModal = document.getElementById("same-device-modal");
  if (existingModal) {
    existingModal.remove();
  }

  const modal = document.createElement("div");
  modal.id = "same-device-modal";
  modal.innerHTML = `
    <div style="
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
    ">
      <div style="
        background: white;
        border-radius: 12px;
        padding: 32px;
        max-width: 400px;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
      ">
        <h2 style="margin: 0 0 16px 0; color: #1a1a2e; font-size: 24px;">
          Open Wallet App
        </h2>
        <p style="color: #666; margin-bottom: 24px; line-height: 1.5;">
          Click the button below to open your EUDI Wallet app and share your credentials.
        </p>
        
        <button
          id="open-wallet-btn"
          style="
            display: inline-block;
            background: #3b82f6;
            color: white;
            padding: 14px 28px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            text-decoration: none;
            margin-bottom: 16px;
            transition: background 0.2s;
            border: none;
            cursor: pointer;
          "
        >
          Open EUDI Wallet
        </button>
        
        <div style="
          margin-top: 20px;
          padding-top: 20px;
          border-top: 1px solid #e5e5e5;
        ">
          <p style="color: #888; font-size: 14px; margin-bottom: 12px;">
            Waiting for response from wallet...
          </p>
          <div id="same-device-spinner" style="
            width: 24px;
            height: 24px;
            border: 3px solid #e5e5e5;
            border-top-color: #3b82f6;
            border-radius: 50%;
            margin: 0 auto;
            animation: spin 1s linear infinite;
          "></div>
        </div>
        
        <button 
          id="cancel-same-device-btn"
          style="
            margin-top: 20px;
            background: none;
            border: none;
            color: #888;
            cursor: pointer;
            font-size: 14px;
            text-decoration: underline;
          "
        >
          Cancel
        </button>
      </div>
    </div>
    <style>
      @keyframes spin {
        to { transform: rotate(360deg); }
      }
    </style>
  `;

  document.body.appendChild(modal);

  // Add cancel button handler
  const cancelBtn = document.getElementById("cancel-same-device-btn");
  if (cancelBtn) {
    cancelBtn.addEventListener("click", () => {
      hideSameDeviceModal();
      logger.log("User cancelled same-device flow");
      onCancel();
    });
  }

  // Open the wallet deep link without navigating the current page.
  // For custom URI schemes (av://, openid4vp://) window.location.href triggers the
  // app on mobile without leaving the page. For https:// authorization-request
  // URIs, window.open opens a new tab so the RP page stays alive.
  const openBtn = document.getElementById("open-wallet-btn");
  if (openBtn) {
    openBtn.addEventListener("click", () => {
      logger.log("Opening wallet app via deep link", {
        deepLinkUri,
        transactionId,
      });
      if (
        deepLinkUri.startsWith("https://") ||
        deepLinkUri.startsWith("http://")
      ) {
        globalThis.open(deepLinkUri, "_blank", "noopener,noreferrer");
      } else {
        // Custom scheme (av://, openid4vp://) — triggers wallet app on mobile,
        // does NOT navigate away from the RP page.
        globalThis.location.href = deepLinkUri;
      }
    });
  }
}

/**
 * Hide the same-device modal
 */
function hideSameDeviceModal(): void {
  const modal = document.getElementById("same-device-modal");
  if (modal) {
    modal.remove();
  }
}

/**
 * Simulate a credential response for demo purposes
 * In production, this would be replaced by actual Digital Credentials API integration
 */
function simulateCredentialResponse(
  request: InitTransactionRequest,
  logger: DebugLogger,
): OpenID4VPResponse {
  logger.log("Simulating credential response");

  // Extract requested claims from the DCQL query
  const requestedClaims: Record<string, unknown> = {};
  const credentialQuery = request.dcql_query?.credentials[0];
  const claimIds =
    credentialQuery?.claims?.map((c) => c.id ?? c.path[c.path.length - 1]) ??
    [];

  claimIds.forEach((claimId) => {
    if (claimId) requestedClaims[claimId] = getDemoValue(claimId);
  });

  const namespace =
    credentialQuery?.claims?.[0]?.path[0] ?? "org.iso.18013.5.1";

  const vpToken = {
    docType: credentialQuery?.meta?.doctype_value ?? "VerifiableCredential",
    issuerSigned: {
      nameSpaces: {
        [namespace]: requestedClaims,
      },
    },
    deviceSigned: {
      deviceAuth: { deviceSignature: btoa(uuidv4()) },
    },
  };

  const response: OpenID4VPResponse = {
    vp_token: btoa(JSON.stringify(vpToken)),
    presentation_submission: null,
  };

  logger.log("Simulated response generated", response);
  return response;
}

/**
 * Generate demo values for claims
 */
function getDemoValue(claimId: string): unknown {
  const demoValues: Record<string, unknown> = {
    family_name: "Smith",
    given_name: "John",
    birth_date: "1990-01-15",
    portrait: null,
    age_over_21: true,
    age_over_18: true,
    age_over_65: false,
    document_number:
      "DL-" + Math.random().toString(36).substring(2, 10).toUpperCase(),
    issue_date: "2023-01-01",
    expiry_date: "2028-01-01",
    issuing_authority: "Department of Motor Vehicles",
    issuing_country: "US",
    nationality: "US",
    resident_address: "123 Main St, Anytown, ST 12345",
    gender: "M",
    driving_privileges: ["A", "B", "C"],
  };

  return demoValues[claimId] ?? `Demo ${claimId}`;
}

/**
 * Send credential to backend for verification
 * The backend will proxy the request to the Credential Verifier server
 */
export async function sendToBackend(
  response: OpenID4VPResponse,
  originalRequest: InitTransactionRequest | null,
  logger: DebugLogger,
): Promise<VerifyResponse> {
  const backendUrl = "/api/verify";

  const body = {
    vp_token: response.vp_token,
    presentation_submission: response.presentation_submission ?? null,
    nonce: originalRequest?.nonce,
    state: response.state,
  };

  logger.log(`Sending to backend: POST ${backendUrl}`, {
    vp_token_length: body.vp_token?.length,
    has_presentation_submission: body.presentation_submission !== null,
    nonce: body.nonce,
    state: body.state,
  });

  try {
    const fetchResponse = await fetch(backendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    logger.log(`Backend responded: HTTP ${fetchResponse.status}`);

    if (!fetchResponse.ok) {
      const errText = await fetchResponse
        .text()
        .catch(() => fetchResponse.statusText);
      throw new Error(`Backend returned ${fetchResponse.status}: ${errText}`);
    }

    const result = await fetchResponse.json();
    logger.success("Backend verification complete", result);

    return result as VerifyResponse;
  } catch (error) {
    logger.error("Backend verification failed", error);
    return {
      success: false,
      message: "Backend verification failed",
      errors: [error instanceof Error ? error.message : "Unknown error"],
    };
  }
}
