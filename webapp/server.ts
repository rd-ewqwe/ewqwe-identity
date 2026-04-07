/// <reference lib="deno.ns" />

/**
 * EU Age Verification Webapp — Backend Server
 *
 * Thin HTTP router that delegates all OpenID4VP logic to the library.
 *
 * Endpoints:
 *   POST /api/openid4vp/init         — Initialize a new transaction (QR/deep-link)
 *   GET  /api/openid4vp/status/:id   — Poll transaction status
 *   POST /api/openid4vp/direct_post  — Wallet posts VP token here
 *   GET  /api/openid4vp/request/:id  — Wallet fetches authorization request (JAR)
 *   GET  /api/openid4vp/.well-known/jwks.json — Public JWK Set
 *   POST /api/verify                 — Proxy verification to credential verifier
 *   GET  /api/health                 — Health check
 */

import {
  OpenID4VPService,
  NotFoundError,
  ExpiredError,
  BadRequestError,
  VerifierError,
} from "@ewqwe/digital-identity-backend";
import type {
  InitTransactionRequest,
  VerifyRequest,
} from "@ewqwe/digital-identity-backend";

// ============================================================================
// Configuration (from environment)
// ============================================================================

const SERVER_PORT = 5175;
const CREDENTIAL_VERIFIER_URL =
  Deno.env.get("CREDENTIAL_VERIFIER_URL") || "https://127.0.0.1:9443";
const PUBLIC_URL =
  Deno.env.get("PUBLIC_URL") || `http://localhost:${SERVER_PORT}`;
const X509_CERT_PATH =
  Deno.env.get("X509_CERT_PATH") || "../ewqwe.com/fullchain1.pem";
const X509_KEY_PATH =
  Deno.env.get("X509_KEY_PATH") || "../ewqwe.com/privkey1.pem";
const CA_CERT_PATH =
  Deno.env.get("CA_CERT_PATH") ||
  "../credential_verifier/src/tests/certificates/ec/ewqwe.chain.pem";

// ============================================================================
// CORS
// ============================================================================

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

// ============================================================================
// Initialize the OpenID4VP service
// ============================================================================

const service = await OpenID4VPService.create({
  publicUrl: PUBLIC_URL,
  credentialVerifierUrl: CREDENTIAL_VERIFIER_URL,
  x509CertPath: X509_CERT_PATH,
  x509KeyPath: X509_KEY_PATH,
  caCertPath: CA_CERT_PATH,
});

// ============================================================================
// HTTP Response Helpers
// ============================================================================

function jsonResponse(
  data: unknown,
  status = 200,
  extraHeaders?: Record<string, string>,
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...CORS_HEADERS,
      ...extraHeaders,
    },
  });
}

function rawResponse(
  body: string,
  contentType: string,
  status = 200,
): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": contentType, ...CORS_HEADERS },
  });
}

function errorResponse(
  message: string,
  status: number,
  errors?: string[],
): Response {
  return jsonResponse(
    { success: false, message, ...(errors ? { errors } : {}) },
    status,
  );
}

// ============================================================================
// Route Handlers
// ============================================================================

async function handleInitTransaction(req: Request): Promise<Response> {
  console.log("\n" + "=".repeat(60));
  console.log("[Server] POST /api/openid4vp/init");
  console.log("=".repeat(60));

  const body: InitTransactionRequest = await req.json();
  const result = await service.initTransaction(body);

  console.log(
    `[Server] Transaction ${result.transaction_id.slice(0, 8)}... created (profile=${result.profile})`,
  );
  return jsonResponse(result);
}

function handleGetStatus(transactionId: string): Response {
  const result = service.getTransactionStatus(transactionId);
  return jsonResponse(result);
}

async function handleDirectPost(req: Request): Promise<Response> {
  console.log("\n" + "=".repeat(60));
  console.log("[Server] POST /api/openid4vp/direct_post");
  console.log("=".repeat(60));

  const contentType = req.headers.get("content-type") || "";

  if (contentType.includes("application/x-www-form-urlencoded")) {
    const formData = await req.formData();
    const jweResponse = formData.get("response") as string | null;

    if (jweResponse) {
      // HAIP: JWE-encrypted response
      console.log(
        `[Server] JWE response received (length=${jweResponse.length})`,
      );
      const fallbackState = (formData.get("state") as string) || undefined;
      await service.handleWalletResponse(null, jweResponse, fallbackState);
    } else {
      // Annex A: Plain form data
      const vpToken = formData.get("vp_token") as string;
      const presentationSubmission = formData.get(
        "presentation_submission",
      ) as string;
      const state = formData.get("state") as string;
      console.log(
        `[Server] Plain direct_post received (state=${state?.slice(0, 8)}...)`,
      );
      await service.handleWalletResponse({
        vpToken,
        presentationSubmission,
        state,
      });
    }
  } else {
    const body = await req.json();
    console.log(
      `[Server] JSON direct_post received (state=${body.state?.slice(0, 8)}...)`,
    );
    await service.handleWalletResponse({
      vpToken: body.vp_token,
      presentationSubmission: body.presentation_submission,
      state: body.state,
    });
  }

  console.log("[Server] Wallet response stored successfully");
  return jsonResponse({ status: "ok" });
}

async function handleGetAuthorizationRequest(
  transactionId: string,
): Promise<Response> {
  console.log("\n" + "=".repeat(60));
  console.log(
    `[Server] GET /api/openid4vp/request/${transactionId.slice(0, 8)}...`,
  );
  console.log("=".repeat(60));

  const result = await service.getAuthorizationRequest(transactionId);
  console.log(`[Server] Returning ${result.contentType}`);
  return rawResponse(result.body, result.contentType);
}

function handleGetJwks(): Response {
  console.log("[Server] GET /api/openid4vp/.well-known/jwks.json");
  const jwks = service.getPublicJwkSet();
  return rawResponse(JSON.stringify(jwks), "application/jwk-set+json");
}

async function handleVerify(req: Request): Promise<Response> {
  console.log("\n" + "=".repeat(60));
  console.log("[Server] POST /api/verify");
  console.log("=".repeat(60));

  const body: VerifyRequest = await req.json();

  // Add client_id from request origin
  const origin = req.headers.get("origin") || "unknown";
  body.client_id = origin;

  const vpTokenPreview =
    typeof body.vp_token === "string"
      ? body.vp_token.substring(0, 100) + "..."
      : JSON.stringify(body.vp_token).substring(0, 200) + "...";
  console.log(`[Server] VP Token (${typeof body.vp_token}): ${vpTokenPreview}`);
  console.log(`[Server] Nonce: ${body.nonce}`);

  const result = await service.verifyCredential(body);

  console.log(`[Server] Verification result: success=${result.success}`);
  return jsonResponse(result);
}

// ============================================================================
// Router
// ============================================================================

async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  // CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  try {
    // OpenID4VP endpoints
    if (path === "/api/openid4vp/init" && req.method === "POST") {
      return await handleInitTransaction(req);
    }

    if (path.startsWith("/api/openid4vp/status/") && req.method === "GET") {
      const transactionId = path.replace("/api/openid4vp/status/", "");
      return handleGetStatus(transactionId);
    }

    if (path === "/api/openid4vp/direct_post" && req.method === "POST") {
      return await handleDirectPost(req);
    }

    if (
      path.startsWith("/api/openid4vp/request/") &&
      (req.method === "GET" || req.method === "POST")
    ) {
      const transactionId = path.replace("/api/openid4vp/request/", "");
      return await handleGetAuthorizationRequest(transactionId);
    }

    if (
      path === "/api/openid4vp/.well-known/jwks.json" &&
      req.method === "GET"
    ) {
      return handleGetJwks();
    }

    // Verification proxy
    if (path === "/api/verify" && req.method === "POST") {
      return await handleVerify(req);
    }

    // Health check
    if (path === "/api/health") {
      return jsonResponse({ status: "ok" });
    }

    return jsonResponse({ error: "Not found" }, 404);
  } catch (error) {
    // Map library errors to HTTP status codes
    if (error instanceof NotFoundError) {
      return jsonResponse({ error: error.message }, 404);
    }
    if (error instanceof ExpiredError) {
      return jsonResponse({ error: error.message, status: "expired" }, 410);
    }
    if (error instanceof BadRequestError) {
      return jsonResponse({ error: error.message }, 400);
    }
    if (error instanceof VerifierError) {
      return errorResponse(error.message, error.status, [error.responseText]);
    }

    console.error("[Server] Unhandled error:", error);
    const msg = error instanceof Error ? error.message : "Unknown error";
    return errorResponse(msg, 500, [msg]);
  }
}

// ============================================================================
// Start Server
// ============================================================================

console.log(`[Server] Starting webapp API server on port ${SERVER_PORT}`);
console.log(`[Server] Public URL: ${PUBLIC_URL}`);
console.log(`[Server] Credential Verifier: ${CREDENTIAL_VERIFIER_URL}`);

Deno.serve({ port: SERVER_PORT }, handleRequest);
