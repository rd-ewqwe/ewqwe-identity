import type {
  OpenID4VPRequest,
  OpenID4VPResponse,
  PresentationDefinition,
  PresentationSubmission,
  InputDescriptor,
  ConstraintField,
  VerifyResponse,
} from "./types.ts";
import type { DebugLogger } from "./debug.ts";
import { CREDENTIAL_TYPES, PROTOCOL_PROFILES } from "./config.ts";

/**
 * Detect whether the browser is running on a mobile device (Android or iOS).
 */
function isMobileDevice(): boolean {
  const ua = navigator.userAgent || "";
  return /android/i.test(ua) || /iphone|ipad|ipod/i.test(ua);
}

/**
 * Build an OpenID4VP presentation request
 */
export function buildPresentationRequest(
  credentialType: string,
  selectedClaims: string[],
  _protocol: string,
): OpenID4VPRequest {
  const config = CREDENTIAL_TYPES[credentialType];
  if (!config) {
    throw new Error(`Unknown credential type: ${credentialType}`);
  }

  const profile = PROTOCOL_PROFILES[config.profile];
  const nonce = crypto.randomUUID();
  const state = crypto.randomUUID();

  // Build constraint fields from selected claims
  const fields: ConstraintField[] = selectedClaims.map((claimId) => {
    const claim = config.claims.find((c) => c.id === claimId);
    return {
      path: [`$['${config.namespace}']['${claimId}']`],
      id: claimId,
      name: claim?.name || claimId,
      intent_to_retain: false,
    };
  });

  const inputDescriptor: InputDescriptor = {
    id: `${credentialType}_credential`,
    name: config.name,
    purpose: `We need to verify your ${config.name.toLowerCase()}`,
    format: {
      mso_mdoc: {
        alg: ["ES256", "ES384", "ES512", "EdDSA"],
      },
    },
    constraints: {
      limit_disclosure: "required",
      fields,
    },
  };

  const presentationDefinition: PresentationDefinition = {
    id: crypto.randomUUID(),
    name: `${config.name} Verification`,
    purpose: `Verify identity using ${config.name}`,
    input_descriptors: [inputDescriptor],
  };

  return {
    client_id: window.location.origin,
    client_id_scheme: profile?.clientIdScheme || "redirect_uri",
    response_type: "vp_token",
    response_mode: profile?.responseMode || "direct_post",
    nonce,
    state,
    presentation_definition: presentationDefinition,
    client_metadata: {
      client_name: "Digital Credentials Demo",
      client_purpose: "Identity verification for demo purposes",
      vp_formats: {
        mso_mdoc: { alg: ["ES256", "ES384", "ES512", "EdDSA"] },
        jwt_vp: { alg: ["ES256", "ES384", "ES512", "EdDSA"] },
      },
    },
    // Include credential type for profile determination on backend
    credential_type: credentialType,
  } as OpenID4VPRequest & { credential_type: string };
}

/**
 * Request credentials using the specified protocol
 * @param request The OpenID4VP request
 * @param protocol The protocol to use
 * @param logger Debug logger
 */
export async function requestCredentials(
  request: OpenID4VPRequest,
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
  request: OpenID4VPRequest,
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
  request: OpenID4VPRequest,
  logger: DebugLogger,
): Promise<OpenID4VPResponse | null> {
  // Try native Digital Credentials API first
  logger.log(
    "Requesting credentials via native Digital Credentials API",
    request,
  );

  const credential = await navigator.credentials.get({
    digital: {
      requests: [
        {
          protocol: "openid4vp",
          data: request,
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
  request: OpenID4VPRequest & { credential_type?: string },
  logger: DebugLogger,
): Promise<OpenID4VPResponse | null> {
  logger.log("OpenID4VP cross-device flow - initializing transaction");

  // Build the init request - supports both DCQL and legacy presentation_definition
  // The backend will convert presentation_definition to DCQL if needed
  const initRequest: {
    dcql_query?: unknown;
    presentation_definition?: unknown;
    nonce?: string;
    client_metadata?: unknown;
    credential_type?: string;
  } = {
    nonce: request.nonce,
    client_metadata: request.client_metadata,
  };

  // Include credential_type for profile determination on backend
  if (request.credential_type) {
    initRequest.credential_type = request.credential_type;
    logger.log(`Credential type: ${request.credential_type}`);
  }

  // If we have a presentation_definition, include it (backend will convert to DCQL)
  if (request.presentation_definition) {
    initRequest.presentation_definition = request.presentation_definition;
  }

  // Step 1: Initialize the transaction on the backend
  const initResponse = await fetch("/api/openid4vp/init", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(initRequest),
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
        typeof response.presentation_submission === "string"
          ? JSON.parse(response.presentation_submission)
          : response.presentation_submission,
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
  request: OpenID4VPRequest & { credential_type?: string },
  logger: DebugLogger,
): Promise<OpenID4VPResponse | null> {
  logger.log("OpenID4VP same-device flow requested");

  // Step 1: Initialize the transaction on the backend
  logger.log("Initializing OpenID4VP transaction for same-device flow...");

  // Build the init request - supports both DCQL and legacy presentation_definition
  const initRequest: {
    dcql_query?: unknown;
    presentation_definition?: unknown;
    nonce?: string;
    mode?: string;
    credential_type?: string;
  } = {
    nonce: request.nonce,
    mode: "same-device",
  };

  // Include credential_type for profile determination on backend
  if (request.credential_type) {
    initRequest.credential_type = request.credential_type;
    logger.log(`Credential type: ${request.credential_type}`);
  }

  // If we have a presentation_definition, include it (backend will convert to DCQL)
  if (request.presentation_definition) {
    initRequest.presentation_definition = request.presentation_definition;
  }

  const initResponse = await fetch("/api/openid4vp/init", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(initRequest),
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
        pollResponse.presentation_submission as PresentationSubmission,
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
        
        <a 
          id="open-wallet-btn"
          href="${deepLinkUri}"
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
          "
        >
          Open EUDI Wallet
        </a>
        
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

  // Log when wallet link is clicked
  const openBtn = document.getElementById("open-wallet-btn");
  if (openBtn) {
    openBtn.addEventListener("click", () => {
      logger.log("Opening wallet app via deep link", {
        deepLinkUri,
        transactionId,
      });
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
  request: OpenID4VPRequest,
  logger: DebugLogger,
): OpenID4VPResponse {
  logger.log("Simulating credential response");

  // Extract requested claims from the presentation definition
  const requestedClaims: Record<string, unknown> = {};
  const inputDescriptor = request.presentation_definition?.input_descriptors[0];

  if (inputDescriptor?.constraints?.fields) {
    inputDescriptor.constraints.fields.forEach((field) => {
      const claimId = field.id || field.path[0].match(/\['([^']+)'\]$/)?.[1];
      if (claimId) {
        // Generate demo values
        requestedClaims[claimId] = getDemoValue(claimId);
      }
    });
  }

  // Create a simulated VP token (in real implementation, this would be a signed JWT or CBOR)
  const vpToken = {
    docType: inputDescriptor?.format?.mso_mdoc
      ? "org.iso.18013.5.1.mDL"
      : "VerifiableCredential",
    issuerSigned: {
      nameSpaces: {
        "org.iso.18013.5.1": requestedClaims,
      },
    },
    deviceSigned: {
      deviceAuth: {
        deviceSignature: btoa(crypto.randomUUID()),
      },
    },
  };

  const response: OpenID4VPResponse = {
    vp_token: btoa(JSON.stringify(vpToken)),
    presentation_submission: {
      id: crypto.randomUUID(),
      definition_id: request.presentation_definition?.id ?? "default",
      descriptor_map: [
        {
          id: inputDescriptor?.id || "credential",
          format: "mso_mdoc",
          path: "$",
        },
      ],
    },
    state: request.state,
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

// /**
//  * Verify the received credential
//  * In production, this would send the credential to a backend server for verification
//  */
// export async function verifyCredential(
//   response: OpenID4VPResponse,
//   originalRequest: OpenID4VPRequest,
//   logger: DebugLogger,
// ): Promise<VerificationResult> {
//   logger.log("Verifying credential", { response, originalRequest });

//   // In a real implementation, this would:
//   // 1. Send the vp_token to a backend server
//   // 2. The server would verify the cryptographic signatures
//   // 3. Check the credential against trusted issuers
//   // 4. Validate the nonce matches the original request
//   // 5. Return the verification result

//   // For demo purposes, we'll simulate the verification
//   try {
//     // Parse the VP token (may be JSON string or base64 encoded)
//     let vpToken: Record<string, unknown>;
//     try {
//       // First try parsing as JSON directly
//       vpToken = JSON.parse(response.vp_token);
//     } catch {
//       // Fall back to base64 decoding
//       const vpTokenJson = atob(response.vp_token);
//       vpToken = JSON.parse(vpTokenJson);
//     }

//     logger.log("Decoded VP token", vpToken);

//     // Extract claims - handle both mDoc format and direct claims
//     const claims =
//       vpToken.claims ||
//       vpToken.issuerSigned?.nameSpaces?.["org.iso.18013.5.1"] ||
//       vpToken.issuerSigned?.nameSpaces?.["eu.europa.ec.av.1"] ||
//       {};

//     // Simulate backend verification
//     const verificationDetails = {
//       signatureValid: true,
//       notExpired: true,
//       issuerTrusted: true,
//       timestamp: new Date().toISOString(),
//     };

//     // Simulate a small delay for "verification"
//     await new Promise((resolve) => setTimeout(resolve, 500));

//     logger.success("Credential verified successfully", {
//       claims,
//       verificationDetails,
//     });

//     return {
//       success: true,
//       message: "Credential verified successfully",
//       claims,
//       verificationDetails,
//     };
//   } catch (error) {
//     logger.error("Verification failed", error);

//     return {
//       success: false,
//       message: "Failed to verify credential",
//       errors: [error instanceof Error ? error.message : "Unknown error"],
//     };
//   }
// }

/**
 * Send credential to backend for verification
 * The backend will proxy the request to the Credential Verifier server
 */
export async function sendToBackend(
  response: OpenID4VPResponse,
  originalRequest: OpenID4VPRequest | null,
  logger: DebugLogger,
): Promise<VerifyResponse> {
  const backendUrl = "/api/verify";

  logger.log(`Sending credential to backend: ${backendUrl}`);

  try {
    const fetchResponse = await fetch(backendUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        vp_token: response.vp_token,
        presentation_submission: response.presentation_submission,
        nonce: originalRequest?.nonce,
        state: response.state || originalRequest?.state,
      }),
    });

    if (!fetchResponse.ok) {
      throw new Error(
        `Backend returned ${fetchResponse.status}: ${fetchResponse.statusText}`,
      );
    }

    const result = await fetchResponse.json();
    logger.success("Backend verification complete", result);

    return result as VerifyResponse;
  } catch (error) {
    logger.error("Backend verification failed", error);

    // Return error - don't silently fall back
    return {
      success: false,
      message: "Backend verification failed",
      errors: [error instanceof Error ? error.message : "Unknown error"],
    };
  }
}
