/// <reference lib="deno.ns" />

/**
 * Demo Webapp — Backend Proxy Server
 *
 * Thin HTTP proxy that forwards all OpenID4VP and verification requests
 * to the Rust credential_verifier server. No business logic here.
 *
 * Proxied endpoints (→ credential_verifier):
 *   POST /ewqwe_api/openid4vp/init         — Initialize a new transaction
 *   GET  /ewqwe_api/openid4vp/status/:id   — Poll transaction status
 *   POST /ewqwe_api/openid4vp/direct_post  — Wallet posts VP token
 *   GET  /ewqwe_api/openid4vp/request/:id  — Wallet fetches authorization request
 *   POST /ewqwe_api/openid4vp/request/:id  — Wallet posts to authorization request
 *   GET  /ewqwe_api/openid4vp/.well-known/jwks.json — Public JWK Set
 *   POST /ewqwe_api/verify                 — Credential verification
 */

// ============================================================================
// Configuration (from environment)
// ============================================================================

const SERVER_PORT = 5175;
const CREDENTIAL_VERIFIER_URL =
  Deno.env.get("CREDENTIAL_VERIFIER_URL") || "https://127.0.0.1:9443";
const CA_CERT_PATH =
  Deno.env.get("CA_CERT_PATH") ||
  "../certificates/tls/ewqwe.ca.pem";

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

// Cache the PEM so we can recreate the client without hitting the filesystem.
/**
 * Create a fresh HttpClient, re-reading the CA cert from disk each time.
 *
 * Re-reading on every call means a cert rotation (e.g. `generate_certs_p256.sh`
 * while the server is running) is automatically recovered on the next
 * connection-error retry — no server restart required.
 *
 * poolIdleTimeout (ms) — drop idle connections after 30 s so Deno never
 * tries to reuse a connection that the upstream server (actix-web / OpenSSL)
 * has already closed during inactivity.
 */
async function makeHttpClient(): Promise<Deno.HttpClient | undefined> {
  try {
    const caCertPem = await Deno.readTextFile(CA_CERT_PATH);
    return Deno.createHttpClient({
      caCerts: [caCertPem],
      poolIdleTimeout: 30_000,
    });
  } catch (e) {
    console.warn(
      `[Server] Could not load CA cert from ${CA_CERT_PATH}: ${e}. ` +
        `TLS connections to credential_verifier may fail.`,
    );
    return undefined;
  }
}

let httpClient = await makeHttpClient();
console.log(`[Server] Loaded CA cert from ${CA_CERT_PATH}`);

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
  console.log(`[Server] ${req.method} ${upstreamPath} → credential_verifier`);

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

  let upstream: Response;
  try {
    upstream = await fetch(url, fetchOptions);
  } catch (err) {
    // Stale pooled connection: the server closed its end during inactivity and
    // Deno tried to reuse it.  Recreate the client (resets the pool) and retry
    // once.  If the retry also fails the error propagates normally.
    const isConnectError =
      err instanceof TypeError &&
      (err.message.includes("Connect") ||
        err.message.includes("TLS") ||
        err.message.includes("InternalError") ||
        err.message.includes("connection"));
    if (!isConnectError) throw err;

    console.warn(
      `[Server] Connection error on ${req.method} ${upstreamPath}, ` +
        `recreating HTTP client and retrying once…`,
    );
    httpClient?.close();
    httpClient = await makeHttpClient();
    if (httpClient) fetchOptions.client = httpClient;
    upstream = await fetch(url, fetchOptions);
  }

  console.log(`    → ${upstream.status}`);

  // Buffer the body fully before responding — streaming upstream.body directly
  // causes AbortError when Vite's HTTP proxy closes the connection prematurely.
  const body = await upstream.arrayBuffer();

  // Build proxied response with CORS
  const respHeaders = new Headers();
  for (const [k, v] of upstream.headers.entries()) {
    respHeaders.set(k, v);
  }
  for (const [k, v] of Object.entries(CORS_HEADERS)) {
    respHeaders.set(k, v);
  }

  return new Response(body, {
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
    // ── All API requests — straight proxy ─────────────────────
    if (path.startsWith("/ewqwe_api/")) {
      return await proxyToVerifier(path, req);
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
console.log(`[Server] Credential Verifier URL: ${CREDENTIAL_VERIFIER_URL}`);

Deno.serve({ port: SERVER_PORT }, handleRequest);
