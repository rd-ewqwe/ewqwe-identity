/// <reference lib="deno.ns" />

/**
 * EU Age Verification Webapp — Backend Proxy Server
 *
 * Thin HTTP proxy that forwards all OpenID4VP and verification requests
 * to the Rust credential_verifier server. No business logic here.
 *
 * Proxied endpoints (→ credential_verifier):
 *   POST /api/openid4vp/init         — Initialize a new transaction
 *   GET  /api/openid4vp/status/:id   — Poll transaction status
 *   POST /api/openid4vp/direct_post  — Wallet posts VP token
 *   GET  /api/openid4vp/request/:id  — Wallet fetches authorization request
 *   POST /api/openid4vp/request/:id  — Wallet posts to authorization request
 *   GET  /api/openid4vp/.well-known/jwks.json — Public JWK Set
 *   POST /api/verify                 — Credential verification
 *
 * Local endpoints:
 *   GET  /api/health                 — Health check
 */

// ============================================================================
// Configuration (from environment)
// ============================================================================

const SERVER_PORT = 5175;
const CREDENTIAL_VERIFIER_URL =
  Deno.env.get("CREDENTIAL_VERIFIER_URL") || "https://127.0.0.1:9443";
const PUBLIC_URL =
  Deno.env.get("PUBLIC_URL") || `http://localhost:${SERVER_PORT}`;
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
// TLS-aware HTTP client for self-signed credential_verifier certs
// ============================================================================

let httpClient: Deno.HttpClient | undefined;

try {
  const caCert = await Deno.readTextFile(CA_CERT_PATH);
  httpClient = Deno.createHttpClient({ caCerts: [caCert] });
  console.log(`[Server] Loaded CA cert from ${CA_CERT_PATH}`);
} catch (e) {
  console.warn(
    `[Server] Could not load CA cert from ${CA_CERT_PATH}: ${e}. ` +
      `TLS connections to credential_verifier may fail.`,
  );
}

// ============================================================================
// Proxy Helper
// ============================================================================

/**
 * Forward a request to the credential_verifier, copying method, headers,
 * and body. Returns the upstream response with CORS headers added.
 */
async function proxyToVerifier(
  upstreamPath: string,
  req: Request,
  bodyOverride?: string,
): Promise<Response> {
  const url = `${CREDENTIAL_VERIFIER_URL}${upstreamPath}`;

  const headers = new Headers();
  // Forward content-type
  const ct = req.headers.get("content-type");
  if (ct) headers.set("content-type", ct);

  const fetchOptions: RequestInit & { client?: Deno.HttpClient } = {
    method: req.method,
    headers,
  };

  // Attach body for POST/PUT/PATCH
  if (req.method !== "GET" && req.method !== "HEAD") {
    fetchOptions.body = bodyOverride ?? (await req.text());
  }

  if (httpClient) {
    fetchOptions.client = httpClient;
  }

  const upstream = await fetch(url, fetchOptions);

  console.log(
    `[Server] Proxied ${req.method} ${upstreamPath} → ${upstream.status}`,
  );

  // Build proxied response with CORS
  const respHeaders = new Headers();
  for (const [k, v] of upstream.headers.entries()) {
    respHeaders.set(k, v);
  }
  for (const [k, v] of Object.entries(CORS_HEADERS)) {
    respHeaders.set(k, v);
  }

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: respHeaders,
  });
}

// ============================================================================
// Response Helpers
// ============================================================================

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...CORS_HEADERS,
    },
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
    // ── OpenID4VP init (inject public_url) ──────────────────────────────
    if (path === "/api/openid4vp/init" && req.method === "POST") {
      console.log("[Server] POST /api/openid4vp/init → credential_verifier");

      // Parse body, inject public_url, forward
      const body = await req.json();
      body.public_url = PUBLIC_URL;
      return await proxyToVerifier(
        "/api/openid4vp/init",
        req,
        JSON.stringify(body),
      );
    }

    // ── All other /api/openid4vp/* — straight proxy ─────────────────────
    if (path.startsWith("/api/openid4vp/")) {
      console.log(`[Server] ${req.method} ${path} → credential_verifier`);
      return await proxyToVerifier(path, req);
    }

    // ── Verification proxy ──────────────────────────────────────────────
    if (path === "/api/verify" && req.method === "POST") {
      console.log("[Server] POST /api/verify → credential_verifier");
      return await proxyToVerifier("/api/verify", req);
    }

    // ── Health check (local) ────────────────────────────────────────────
    if (path === "/api/health") {
      return jsonResponse({ status: "ok" });
    }

    return jsonResponse({ error: "Not found" }, 404);
  } catch (error) {
    console.error("[Server] Proxy error:", error);
    const msg = error instanceof Error ? error.message : "Unknown error";
    return errorResponse(msg, 502, [msg]);
  }
}

// ============================================================================
// Start Server
// ============================================================================

console.log(`[Server] Starting webapp proxy server on port ${SERVER_PORT}`);
console.log(`[Server] Public URL: ${PUBLIC_URL}`);
console.log(`[Server] Credential Verifier: ${CREDENTIAL_VERIFIER_URL}`);

Deno.serve({ port: SERVER_PORT }, handleRequest);
