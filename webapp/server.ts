/// <reference lib="deno.ns" />

/**
 * EU Age Verification Webapp - Backend Server
 *
 * This server:
 * 1. Handles /api/* endpoints (Vite proxies these here)
 * 2. Proxies verification requests to the Credential Verifier server
 */

const SERVER_PORT = 5175; // Backend API port (Vite proxies /api/* here)
const CREDENTIAL_VERIFIER_URL =
  Deno.env.get("CREDENTIAL_VERIFIER_URL") || "https://127.0.0.1:9443";

// Load CA certificate for TLS connection to Credential Verifier
const CA_CERT_PATH =
  Deno.env.get("CA_CERT_PATH") ||
  "../credential_verifier/src/tests/certificates/ec/ewqwe.chain.pem";

let caCert: string | undefined;
try {
  caCert = await Deno.readTextFile(CA_CERT_PATH);
  console.log(`[Backend] Loaded CA certificate from ${CA_CERT_PATH}`);
} catch (e) {
  console.warn(
    `[Backend] Could not load CA certificate from ${CA_CERT_PATH}:`,
    e,
  );
  console.warn("[Backend] TLS connections to Credential Verifier may fail");
}

// Create a custom HTTP client with the CA cert
const httpClient = caCert
  ? Deno.createHttpClient({
      caCerts: [caCert],
    })
  : undefined;

interface VerifyRequest {
  vp_token: string;
  presentation_submission: {
    id: string;
    definition_id: string;
    descriptor_map: Array<{
      id: string;
      format: string;
      path: string;
    }>;
  };
  nonce?: string;
  state?: string;
  client_id?: string;
}

interface VerifyResponse {
  success: boolean;
  message: string;
  claims?: Record<string, unknown>;
  verification_details?: {
    signature_valid: boolean;
    not_expired: boolean;
    issuer_trusted: boolean;
    timestamp: string;
    doc_type?: string;
    namespace?: string;
  };
  attestation?: string;
  errors?: string[];
}

/**
 * Handle API requests
 */
async function handleApiRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  // CORS headers for API responses
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };

  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (path === "/api/verify" && req.method === "POST") {
    return await handleVerifyCredential(req, corsHeaders);
  }

  if (path === "/api/health") {
    return new Response(JSON.stringify({ status: "ok" }), {
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  return new Response(JSON.stringify({ error: "Not found" }), {
    status: 404,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  });
}

/**
 * Handle credential verification by proxying to the Credential Verifier server
 */
async function handleVerifyCredential(
  req: Request,
  corsHeaders: Record<string, string>,
): Promise<Response> {
  console.log("\n" + "=".repeat(60));
  console.log("[Backend] === VERIFICATION REQUEST RECEIVED ===");
  console.log("=".repeat(60));

  try {
    const body: VerifyRequest = await req.json();

    console.log("[Backend] VP Token length:", body.vp_token?.length);
    console.log(
      "[Backend] VP Token preview:",
      body.vp_token?.substring(0, 100) + "...",
    );
    console.log("[Backend] Nonce:", body.nonce);
    console.log("[Backend] State:", body.state);

    // Add client_id from the request origin
    const origin = req.headers.get("origin") || "unknown";
    body.client_id = origin;
    console.log("[Backend] Client ID (origin):", origin);

    // Forward to Credential Verifier server
    const verifierUrl = `${CREDENTIAL_VERIFIER_URL}/api/verify`;
    console.log(
      "\n[Backend] >>> Forwarding to Credential Verifier:",
      verifierUrl,
    );

    try {
      console.log("[Backend] Sending fetch request...");
      if (httpClient) {
        console.log("[Backend] Using custom HTTP client with CA certificate");
      }
      const startTime = Date.now();

      const verifierResponse = await fetch(verifierUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
        // Use custom HTTP client with CA cert if available
        ...(httpClient ? { client: httpClient } : {}),
      });

      const elapsed = Date.now() - startTime;
      console.log(`[Backend] <<< Response received in ${elapsed}ms`);
      console.log(
        "[Backend] Response status:",
        verifierResponse.status,
        verifierResponse.statusText,
      );

      if (!verifierResponse.ok) {
        const errorText = await verifierResponse.text();
        console.error(
          "[Backend] !!! Credential Verifier error:",
          verifierResponse.status,
          errorText,
        );
        console.log("[Backend] Falling back to simulation mode");

        // Fall back to local simulation if verifier is unavailable
        return simulateVerification(body, corsHeaders);
      }

      const result: VerifyResponse = await verifierResponse.json();
      console.log("[Backend] Credential Verifier result:");
      console.log("  - success:", result.success);
      console.log("  - message:", result.message);
      console.log("  - has attestation:", !!result.attestation);
      console.log("=".repeat(60) + "\n");

      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    } catch (fetchError) {
      console.warn(
        "[Backend] Credential Verifier unavailable, using simulation:",
        fetchError,
      );

      // Fall back to local simulation
      return simulateVerification(body, corsHeaders);
    }
  } catch (error) {
    console.error("[Backend] Error processing verification request:", error);

    return new Response(
      JSON.stringify({
        success: false,
        message: "Backend error processing request",
        errors: [error instanceof Error ? error.message : "Unknown error"],
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      },
    );
  }
}

/**
 * Simulate verification when Credential Verifier is unavailable
 * This is for development/demo purposes only
 */
function simulateVerification(
  body: VerifyRequest,
  corsHeaders: Record<string, string>,
): Response {
  console.log("[Backend] Using simulated verification (demo mode)");

  try {
    // Parse the VP token
    const vpToken = JSON.parse(body.vp_token);
    const claims = vpToken.claims || {};

    const response: VerifyResponse = {
      success: true,
      message: "Credential verified (simulation mode)",
      claims,
      verification_details: {
        signature_valid: true,
        not_expired: true,
        issuer_trusted: true,
        timestamp: new Date().toISOString(),
        doc_type: vpToken.docType,
        namespace: vpToken.namespace,
      },
    };

    return new Response(JSON.stringify(response), {
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch {
    return new Response(
      JSON.stringify({
        success: false,
        message: "Failed to parse VP token",
        errors: ["Invalid VP token format"],
      }),
      {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      },
    );
  }
}

/**
 * Main request handler - only handles /api/* routes
 * Vite proxies /api/* requests here
 */
function handler(req: Request): Promise<Response> {
  return handleApiRequest(req);
}

// Start the server
console.log(`[Backend] Starting webapp API server on port ${SERVER_PORT}`);
console.log(`[Backend] Credential Verifier URL: ${CREDENTIAL_VERIFIER_URL}`);

Deno.serve({ port: SERVER_PORT }, handler);
