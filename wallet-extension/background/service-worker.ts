/**
 * EU Age Verification Wallet - Background Service Worker
 *
 * Handles:
 * - Message passing between content scripts and popup
 * - Credential presentation requests
 * - Extension lifecycle management
 */

import { getCredentialStore } from "../src/store";
import type {
  ExtensionMessage,
  StoredCredential,
  DCQLQuery,
} from "../src/types";

// Cross-browser runtime API
const runtime =
  typeof browser !== "undefined" ? browser.runtime : chrome.runtime;

console.log("[Wallet Service Worker] Starting...");

/**
 * Handle messages from content scripts and popup
 */
runtime.onMessage.addListener(
  (message: ExtensionMessage, sender, sendResponse) => {
    handleMessage(message, sender)
      .then(sendResponse)
      .catch((error) => {
        console.error("[Wallet] Message handling error:", error);
        sendResponse({ error: error.message });
      });

    // Return true to indicate async response
    return true;
  },
);

async function handleMessage(
  message: ExtensionMessage,
  _sender: chrome.runtime.MessageSender,
): Promise<unknown> {
  const store = await getCredentialStore();

  switch (message.type) {
    case "GET_CREDENTIALS":
      return {
        credentials: store.getAll(),
        counts: store.getCountByType(),
      };

    case "GET_CREDENTIAL":
      return store.get(message.id);

    case "RESET_CREDENTIALS":
      await store.reset();
      return {
        credentials: store.getAll(),
        counts: store.getCountByType(),
      };

    case "PRESENT_CREDENTIAL":
      return handlePresentationRequest(message.request);

    case "DC_API_REQUEST":
      return handleDigitalCredentialRequest(message.request);

    default:
      console.warn("[Wallet] Unknown message type:", message);
      return { error: "Unknown message type" };
  }
}

/**
 * Handle OpenID4VP presentation request
 */
async function handlePresentationRequest(request: {
  dcql_query: DCQLQuery;
  nonce: string;
  response_uri: string;
}): Promise<{ matchingCredentials: StoredCredential[] }> {
  const store = await getCredentialStore();

  // Parse DCQL query to find matching credentials
  const matchingCredentials: StoredCredential[] = [];

  for (const credQuery of request.dcql_query.credentials) {
    const docType = credQuery.meta?.doctype_value;
    if (!docType) continue;

    const requestedClaims = credQuery.claims.map(
      (c) => c.path[c.path.length - 1],
    );
    const matches = store.findMatchingCredentials(docType, requestedClaims);
    matchingCredentials.push(...matches);
  }

  console.log(
    "[Wallet] Found matching credentials:",
    matchingCredentials.length,
  );

  return { matchingCredentials };
}

/**
 * Handle W3C Digital Credentials API request
 * This is the primary presentation method per EU AV profile
 */
async function handleDigitalCredentialRequest(request: {
  protocol: string;
  data: {
    deviceRequest?: string;
    encryptionInfo?: string;
    dcql_query?: DCQLQuery;
    presentation_definition?: {
      input_descriptors: Array<{
        id: string;
        name?: string;
        format?: Record<string, unknown>;
        constraints?: {
          fields?: Array<{
            path: string[];
            id?: string;
          }>;
        };
      }>;
    };
    nonce?: string;
    client_id?: string;
  };
}): Promise<{ matchingCredentials: StoredCredential[] }> {
  const store = await getCredentialStore();

  console.log("[Wallet] Handling DC API request:", request);

  // Handle OpenID4VP protocol
  if (
    request.protocol === "openid4vp" &&
    request.data.presentation_definition
  ) {
    const presentationDef = request.data.presentation_definition;
    const matchingCredentials: StoredCredential[] = [];

    for (const descriptor of presentationDef.input_descriptors) {
      // Map descriptor ID to credential type
      const credentialType = mapDescriptorToType(descriptor.id);

      if (credentialType) {
        // Get all credentials of this type
        const credentials = store.getByType(credentialType);

        // Filter by requested claims if specified
        const requestedClaims = descriptor.constraints?.fields
          ?.map((f) => f.id || f.path[0]?.match(/\['([^']+)'\]$/)?.[1])
          .filter(Boolean) as string[];

        if (requestedClaims?.length) {
          // Check that credential has the requested claims
          const matching = credentials.filter((cred) =>
            requestedClaims.some((claim) => claim in cred.claims),
          );
          matchingCredentials.push(...matching);
        } else {
          matchingCredentials.push(...credentials);
        }
      }
    }

    console.log(
      "[Wallet] Found matching credentials for OpenID4VP:",
      matchingCredentials.length,
    );
    return { matchingCredentials };
  }

  // Handle org-iso-mdoc protocol
  if (request.protocol === "org-iso-mdoc") {
    // Parse deviceRequest to extract docType and requested claims
    // For demo, we'll match based on available credentials
    // In production, this would decode CBOR and match properly

    // Return all proof-of-age credentials as they're the primary use case
    const poaCredentials = store.getByType("proof-of-age");
    return { matchingCredentials: poaCredentials };
  }

  if (request.protocol === "openid4vp-v1-unsigned" && request.data.dcql_query) {
    return handlePresentationRequest({
      dcql_query: request.data.dcql_query,
      nonce: request.data.nonce || "",
      response_uri: "",
    });
  }

  // Default: return all credentials
  console.log("[Wallet] Unknown protocol, returning all credentials");
  return { matchingCredentials: store.getAll() };
}

/**
 * Map presentation definition descriptor ID to credential type
 */
function mapDescriptorToType(descriptorId: string): string | null {
  const typeMap: Record<string, string> = {
    mdl_credential: "mdl",
    "national-id_credential": "national-id",
    national_id_credential: "national-id",
    "proof-of-age_credential": "proof-of-age",
    proof_of_age_credential: "proof-of-age",
  };

  return typeMap[descriptorId] || null;
}

/**
 * Extension installation handler
 */
runtime.onInstalled.addListener(async (details) => {
  console.log("[Wallet] Extension installed:", details.reason);

  if (details.reason === "install") {
    // Initialize store with sample credentials on first install
    const store = await getCredentialStore();
    console.log(
      "[Wallet] Initialized with credentials:",
      store.getCountByType(),
    );
  }
});

/**
 * Extension startup handler
 */
runtime.onStartup.addListener(async () => {
  console.log("[Wallet] Extension starting up...");
  await getCredentialStore();
});

console.log("[Wallet Service Worker] Ready");
