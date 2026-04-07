import type {
  OpenID4VPRequest,
  OpenID4VPResponse,
  PresentationDefinition,
  InputDescriptor,
  ConstraintField,
  VerificationResult,
} from "./types.ts";
import type { DebugLogger } from "./debug.ts";
import { CREDENTIAL_TYPES } from "./config.ts";

/**
 * Build an OpenID4VP presentation request
 */
export function buildPresentationRequest(
  credentialType: string,
  selectedClaims: string[],
  protocol: string
): OpenID4VPRequest {
  const config = CREDENTIAL_TYPES[credentialType];
  if (!config) {
    throw new Error(`Unknown credential type: ${credentialType}`);
  }

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
    client_id_scheme: "redirect_uri",
    response_type: "vp_token",
    response_mode: "direct_post",
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
  };
}

/**
 * Request credentials using the Digital Credentials API
 */
export async function requestCredentials(
  request: OpenID4VPRequest,
  logger: DebugLogger
): Promise<OpenID4VPResponse | null> {
  // Check for API support
  if (typeof globalThis.DigitalCredential === "undefined") {
    logger.log("Digital Credentials API not supported, using simulation mode");
    return simulateCredentialResponse(request, logger);
  }

  try {
    logger.log("Requesting credentials via Digital Credentials API", request);

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

    const digitalCredential = credential as unknown as { protocol: string; data: OpenID4VPResponse };
    logger.success("Credential received", digitalCredential);

    return digitalCredential.data;
  } catch (error) {
    logger.error("Failed to request credentials", error);
    
    // Fall back to simulation for demo purposes
    logger.log("Falling back to simulation mode");
    return simulateCredentialResponse(request, logger);
  }
}

/**
 * Simulate a credential response for demo purposes
 * In production, this would be replaced by actual Digital Credentials API integration
 */
function simulateCredentialResponse(
  request: OpenID4VPRequest,
  logger: DebugLogger
): OpenID4VPResponse {
  logger.log("Simulating credential response");

  // Extract requested claims from the presentation definition
  const requestedClaims: Record<string, unknown> = {};
  const inputDescriptor = request.presentation_definition.input_descriptors[0];
  
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
    docType: inputDescriptor?.format?.mso_mdoc ? "org.iso.18013.5.1.mDL" : "VerifiableCredential",
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
      definition_id: request.presentation_definition.id,
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
    document_number: "DL-" + Math.random().toString(36).substring(2, 10).toUpperCase(),
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
 * Verify the received credential
 * In production, this would send the credential to a backend server for verification
 */
export async function verifyCredential(
  response: OpenID4VPResponse,
  originalRequest: OpenID4VPRequest,
  logger: DebugLogger
): Promise<VerificationResult> {
  logger.log("Verifying credential", { response, originalRequest });

  // In a real implementation, this would:
  // 1. Send the vp_token to a backend server
  // 2. The server would verify the cryptographic signatures
  // 3. Check the credential against trusted issuers
  // 4. Validate the nonce matches the original request
  // 5. Return the verification result

  // For demo purposes, we'll simulate the verification
  try {
    // Decode the VP token
    const vpTokenJson = atob(response.vp_token);
    const vpToken = JSON.parse(vpTokenJson);
    
    logger.log("Decoded VP token", vpToken);

    // Extract claims
    const claims = vpToken.issuerSigned?.nameSpaces?.["org.iso.18013.5.1"] || {};

    // Simulate backend verification
    const verificationDetails = {
      signatureValid: true,
      notExpired: true,
      issuerTrusted: true,
      timestamp: new Date().toISOString(),
    };

    // Simulate a small delay for "verification"
    await new Promise((resolve) => setTimeout(resolve, 500));

    logger.success("Credential verified successfully", { claims, verificationDetails });

    return {
      success: true,
      message: "Credential verified successfully",
      claims,
      verificationDetails,
    };
  } catch (error) {
    logger.error("Verification failed", error);
    
    return {
      success: false,
      message: "Failed to verify credential",
      errors: [error instanceof Error ? error.message : "Unknown error"],
    };
  }
}

/**
 * Send credential to backend for verification
 * This is a placeholder for when the Rust backend is implemented
 */
export async function sendToBackend(
  response: OpenID4VPResponse,
  logger: DebugLogger
): Promise<VerificationResult> {
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
      }),
    });

    if (!fetchResponse.ok) {
      throw new Error(`Backend returned ${fetchResponse.status}: ${fetchResponse.statusText}`);
    }

    const result = await fetchResponse.json();
    logger.success("Backend verification complete", result);
    
    return result as VerificationResult;
  } catch (error) {
    logger.error("Backend verification failed, using local simulation", error);
    
    // Fall back to local simulation if backend is not available
    return {
      success: false,
      message: "Backend server not available. The Rust backend will be implemented later.",
      errors: ["Backend not available - verification simulated locally"],
    };
  }
}
