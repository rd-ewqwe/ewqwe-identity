import type {
  InitTransactionRequest,
  InitTransactionResponse,
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
    logger.log(
      `Credential type: ${request.credential_type}, callback url: ${request.public_url}`,
    );
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

  const initData: InitTransactionResponse = await initResponse.json();

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

/** Singleton state for the QR code modal's persistent button handlers. */
const qrCodeModal = {
  authorizationRequestUri: "",
  cancelResolve: null as (() => void) | null,
  logger: null as DebugLogger | null,
  listenersAttached: false,
};

interface QRCodeModal {
  close: () => void;
  onCancel: Promise<void>;
}

/** Hide the QR code modal. */
function closeQRCodeModal(): void {
  document
    .getElementById("openid4vp-qr-modal")
    ?.classList.replace("flex", "hidden");
}

// Copy-icon SVG reused in the QR copy button
const COPY_ICON_SVG = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
    d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
</svg>`;

/**
 * Show the QR code modal (defined as a hidden element in index.html).
 * Dynamic content (badge, wallet name, QR image) is updated on each call.
 * Buttons are wired **once** via the qrCodeModal singleton; state is updated
 * on each call so the handlers always target the current transaction.
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

  const overlay = document.getElementById("openid4vp-qr-modal");
  if (!overlay) {
    logger.error("#openid4vp-qr-modal not found in DOM");
    return { close: closeQRCodeModal, onCancel: new Promise<void>(() => {}) };
  }

  // Fresh promise per call so this transaction's cancellation is independent.
  const onCancel = new Promise<void>((resolve) => {
    qrCodeModal.cancelResolve = resolve;
  });

  // Update singleton state before any listener fires.
  qrCodeModal.authorizationRequestUri = authorizationRequestUri;
  qrCodeModal.logger = logger;

  // ── Update dynamic content ───────────────────────────────────────────────
  const isHaip = profile === "haip";
  const walletName = isHaip ? "EUDI Wallet" : "Age Verification App";

  const badge = document.getElementById("qr-profile-badge");
  if (badge) {
    badge.textContent = isHaip ? "HAIP" : "Annex A";
    badge.className = `inline-block px-2 py-1 text-xs rounded-full ${
      isHaip ? "bg-blue-600" : "bg-green-600"
    }`;
  }

  const walletNameEl = document.getElementById("qr-wallet-name");
  if (walletNameEl) walletNameEl.textContent = walletName;

  // Reset QR container to spinner, then load image
  const qrContainer = document.getElementById("qr-code-container");
  if (qrContainer) {
    qrContainer.innerHTML = `
      <div class="w-64 h-64 flex items-center justify-center">
        <div class="animate-spin w-8 h-8 border-4 border-indigo-500 border-t-transparent rounded-full"></div>
      </div>`;

    const qrImg = document.createElement("img");
    qrImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=256x256&data=${encodeURIComponent(authorizationRequestUri)}`;
    qrImg.alt = "QR Code for wallet";
    qrImg.className = "w-64 h-64";
    qrImg.onload = () => {
      qrContainer.innerHTML = "";
      qrContainer.appendChild(qrImg);
    };
    qrImg.onerror = () => {
      qrContainer.innerHTML = `
        <div class="w-64 h-64 flex flex-col items-center justify-center text-black text-xs p-2 overflow-hidden">
          <p class="font-medium mb-2">QR Code unavailable</p>
          <p class="break-all">${authorizationRequestUri.slice(0, 100)}...</p>
        </div>`;
    };
  }

  if (!qrCodeModal.listenersAttached) {
    qrCodeModal.listenersAttached = true;

    document.getElementById("qr-cancel-btn")?.addEventListener("click", () => {
      qrCodeModal.cancelResolve?.();
      closeQRCodeModal();
    });

    document
      .getElementById("qr-copy-btn")
      ?.addEventListener("click", async () => {
        const copyBtn = document.getElementById(
          "qr-copy-btn",
        ) as HTMLElement | null;
        if (!copyBtn) return;
        try {
          await navigator.clipboard.writeText(
            qrCodeModal.authorizationRequestUri,
          );
          copyBtn.innerHTML = `
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
            </svg>
            Copied!`;
          setTimeout(() => {
            copyBtn.innerHTML = `${COPY_ICON_SVG} Copy Link`;
          }, 2000);
        } catch {
          qrCodeModal.logger?.error("Failed to copy to clipboard");
        }
      });

    // Close on overlay (backdrop) click
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) {
        qrCodeModal.cancelResolve?.();
        closeQRCodeModal();
      }
    });
  }

  overlay.classList.replace("hidden", "flex");
  return { close: closeQRCodeModal, onCancel };
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
    logger.log(
      `Credential type: ${request.credential_type}, url: ${request.public_url}`,
    );
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

  const initData: InitTransactionResponse = await initResponse.json();
  const { transaction_id, authorization_request_uri } = initData;

  if (!authorization_request_uri) {
    throw new Error(
      "Backend did not return a authorization_request_uri for same-device flow",
    );
  }

  logger.log("Transaction initialized", {
    transaction_id,
    authorization_request_uri,
  });

  // Create a cancel promise that will be resolved when user clicks cancel
  let cancelResolve: () => void;
  const cancelPromise = new Promise<void>((resolve) => {
    cancelResolve = resolve;
  });

  // Step 2: Show instructions and open the deep link
  showSameDeviceModal(
    authorization_request_uri,
    transaction_id,
    logger,
    cancelResolve!,
  );

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

/** Singleton state for the same-device modal's persistent button handlers. */
const sameDeviceModal = {
  deepLinkUri: "",
  transactionId: "",
  logger: null as DebugLogger | null,
  onCancel: null as (() => void) | null,
  listenersAttached: false,
};

/**
 * Show the same-device modal (defined as a hidden element in index.html).
 *
 * Button listeners are attached **once** on the first call; each subsequent
 * call only updates the singleton that the handlers already close over,
 * avoiding the clone-and-rewire dance.
 */
function showSameDeviceModal(
  deepLinkUri: string,
  transactionId: string,
  logger: DebugLogger,
  onCancel: () => void,
): void {
  const modal = document.getElementById("same-device-modal");
  if (!modal) {
    logger.error("#same-device-modal not found in DOM");
    return;
  }

  // Update singleton before the modal becomes visible so the handlers
  // always operate on the current transaction.
  sameDeviceModal.deepLinkUri = deepLinkUri;
  sameDeviceModal.transactionId = transactionId;
  sameDeviceModal.logger = logger;
  sameDeviceModal.onCancel = onCancel;

  if (!sameDeviceModal.listenersAttached) {
    sameDeviceModal.listenersAttached = true;

    document
      .getElementById("cancel-same-device-btn")
      ?.addEventListener("click", () => {
        hideSameDeviceModal();
        sameDeviceModal.logger?.log("User cancelled same-device flow");
        sameDeviceModal.onCancel?.();
      });

    // Open the wallet deep link without navigating the current page.
    // For custom URI schemes (av://, openid4vp://) window.location.href triggers
    // the app on mobile without leaving the page. For https:// authorization-
    // request URIs, window.open opens a new tab so the RP page stays alive.
    document
      .getElementById("open-wallet-btn")
      ?.addEventListener("click", () => {
        sameDeviceModal.logger?.log("Opening wallet app via deep link", {
          deepLinkUri: sameDeviceModal.deepLinkUri,
          transactionId: sameDeviceModal.transactionId,
        });
        if (
          sameDeviceModal.deepLinkUri.startsWith("https://") ||
          sameDeviceModal.deepLinkUri.startsWith("http://")
        ) {
          globalThis.open(
            sameDeviceModal.deepLinkUri,
            "_blank",
            "noopener,noreferrer",
          );
        } else {
          // Custom scheme (av://, openid4vp://) — triggers wallet app on mobile.
          globalThis.location.href = sameDeviceModal.deepLinkUri;
        }
      });
  }

  modal.classList.replace("hidden", "flex");
}

/**
 * Hide the same-device modal
 */
function hideSameDeviceModal(): void {
  document
    .getElementById("same-device-modal")
    ?.classList.replace("flex", "hidden");
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
