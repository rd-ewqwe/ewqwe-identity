/// <reference lib="deno.ns" />

// Import jose for JWT signing (JAR - JWT Secured Authorization Request)
import * as jose from "https://deno.land/x/jose@v5.9.6/index.ts";

/**
 * EU Age Verification Webapp - Backend Server
 *
 * This server:
 * 1. Handles /api/* endpoints (Vite proxies these here)
 * 2. Proxies verification requests to the Credential Verifier server
 * 3. Manages OpenID4VP cross-device presentation transactions
 *
 * OpenID4VP Implementation:
 * - Uses DCQL (Digital Credentials Query Language) for credential queries
 * - Returns JAR (JWT Secured Authorization Request) per RFC 9101
 * - Supports cross-device flow with QR codes and same-device flow with deep links
 */

const SERVER_PORT = 5175; // Backend API port (Vite proxies /api/* here)
const CREDENTIAL_VERIFIER_URL =
  Deno.env.get("CREDENTIAL_VERIFIER_URL") || "https://127.0.0.1:9443";

// Public URL for OpenID4VP callbacks (must be accessible from mobile devices)
const PUBLIC_URL =
  Deno.env.get("PUBLIC_URL") || `http://localhost:${SERVER_PORT}`;

// ============================================================================
// X.509 Certificate & JAR Signing Key (for JWT Secured Authorization Requests)
// ============================================================================

// Path to the X.509 certificate chain and private key for JAR signing
// These must have a SAN DNS entry matching the server hostname (e.g., hq.ewqwe.com)
const X509_CERT_PATH =
  Deno.env.get("X509_CERT_PATH") || "../ewqwe.com/fullchain1.pem";
const X509_KEY_PATH =
  Deno.env.get("X509_KEY_PATH") || "../ewqwe.com/privkey1.pem";

// JAR signing state
let jarSigningKey: jose.KeyLike;
let jarSigningKeyJwk: jose.JWK;
// x5c: base64-encoded (NOT base64url) DER certificates for the JWT header
let jarX5cChain: string[];
// The SAN DNS name extracted from the leaf certificate
let jarSanDnsName: string;
const JAR_KEY_ID = "ewqwe-jar-key-1";

/**
 * Parse PEM-encoded certificate chain into individual base64-encoded DER certificates
 * suitable for use in the JWT x5c header (RFC 7515 §4.1.6).
 */
function parsePemCertChain(pemChain: string): string[] {
  const certs: string[] = [];
  const regex =
    /-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/g;
  let match;
  while ((match = regex.exec(pemChain)) !== null) {
    // Remove all whitespace/newlines from the base64 content
    certs.push(match[1].replace(/\s+/g, ""));
  }
  return certs;
}

/**
 * Extract the SAN DNS name from a base64-encoded DER certificate.
 * Uses a simple ASN.1 parsing approach: decode the base64, search for the
 * DNS name in the Subject Alternative Name extension.
 */
function extractSanDnsFromCert(base64Der: string): string | null {
  // Decode base64 to binary
  const der = Uint8Array.from(atob(base64Der), (c) => c.charCodeAt(0));
  // Search for the SAN OID (2.5.29.17 = 55 1d 11) in the DER bytes
  // then extract UTF-8 strings that follow context tag [2] (dNSName)
  for (let i = 0; i < der.length - 4; i++) {
    if (der[i] === 0x55 && der[i + 1] === 0x1d && der[i + 2] === 0x11) {
      // Found SAN OID, now search for context-specific tag [2] (dNSName)
      for (let j = i + 3; j < der.length - 2; j++) {
        if (der[j] === 0x82) {
          // tag [2] = dNSName
          const len = der[j + 1];
          if (len > 0 && j + 2 + len <= der.length) {
            const name = new TextDecoder().decode(
              der.slice(j + 2, j + 2 + len),
            );
            // Validate it looks like a DNS name
            if (/^[a-zA-Z0-9.-]+$/.test(name)) {
              return name;
            }
          }
        }
      }
    }
  }
  return null;
}

async function initializeJarSigningKey() {
  // Load X.509 certificate chain
  const certPem = await Deno.readTextFile(X509_CERT_PATH);
  jarX5cChain = parsePemCertChain(certPem);
  if (jarX5cChain.length === 0) {
    throw new Error(`No certificates found in ${X509_CERT_PATH}`);
  }
  console.log(
    `[JAR] Loaded ${jarX5cChain.length} certificate(s) from ${X509_CERT_PATH}`,
  );

  // Extract SAN DNS name from the leaf certificate
  const sanDns = extractSanDnsFromCert(jarX5cChain[0]);
  if (!sanDns) {
    throw new Error(
      `Could not extract SAN DNS name from leaf certificate in ${X509_CERT_PATH}`,
    );
  }
  jarSanDnsName = sanDns;
  console.log(`[JAR] Certificate SAN DNS: ${jarSanDnsName}`);

  // Load private key (extractable so we can also export the public JWK)
  const keyPem = await Deno.readTextFile(X509_KEY_PATH);
  // Import as a raw CryptoKey with extractable=true, then wrap for jose
  const ecKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(keyPem),
    { name: "ECDSA", namedCurve: "P-256" },
    true, // extractable
    ["sign"],
  );
  jarSigningKey = ecKey as unknown as jose.KeyLike;
  jarSigningKeyJwk = await jose.exportJWK(ecKey);
  jarSigningKeyJwk.kid = JAR_KEY_ID;
  jarSigningKeyJwk.use = "sig";
  jarSigningKeyJwk.alg = "ES256";
  console.log(`[JAR] Loaded private key from ${X509_KEY_PATH}`);
  console.log(`[JAR] Client ID will be: x509_san_dns:${jarSanDnsName}`);
}

/**
 * Convert a PEM-encoded key to an ArrayBuffer (DER).
 */
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Initialize the signing key at startup
await initializeJarSigningKey();

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

// ============================================================================
// OpenID4VP Transaction Management
// ============================================================================

/**
 * DCQL (Digital Credentials Query Language) types
 * See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#dcql
 */
interface DCQLClaimsQuery {
  id?: string;
  path: string[];
  values?: unknown[];
  intent_to_retain?: boolean;
}

interface DCQLCredentialQuery {
  id: string;
  format: "mso_mdoc" | "dc+sd-jwt" | "jwt_vc_json";
  meta?: {
    doctype_value?: string; // For mso_mdoc
    vct_values?: string[]; // For sd-jwt
  };
  claims?: DCQLClaimsQuery[];
  claim_sets?: string[][];
  multiple?: boolean;
  require_cryptographic_holder_binding?: boolean;
}

interface DCQLCredentialSetQuery {
  options: string[][];
  required?: boolean;
  purpose?: string;
}

interface DCQLQuery {
  credentials: DCQLCredentialQuery[];
  credential_sets?: DCQLCredentialSetQuery[];
}

/**
 * Represents an OpenID4VP presentation transaction (cross-device flow)
 * Based on the EUDI Verifier Endpoint implementation
 */
interface OpenID4VPTransaction {
  id: string;
  state: string;
  nonce: string;
  createdAt: number;
  expiresAt: number;
  status: "pending" | "received" | "verified" | "error";
  dcqlQuery: DCQLQuery;
  clientId: string;
  responseUri: string;
  walletResponse?: WalletDirectPostResponse;
  verificationResult?: VerifyResponse;
  errorMessage?: string;
  clientMetadata?: ClientMetadata;
}

interface ClientMetadata {
  client_name?: string;
  logo_uri?: string;
  vp_formats?: {
    mso_mdoc?: {
      // Legacy format with string algorithm names
      alg?: string[];
      // COSE format with algorithm IDs (preferred for EUDI Wallet)
      // ES256=-7, ES384=-35, ES512=-36
      issuerauth_alg_values?: number[];
      deviceauth_alg_values?: number[];
    };
    "dc+sd-jwt"?: {
      "sd-jwt_alg_values"?: string[];
      "kb-jwt_alg_values"?: string[];
    };
  };
  jwks?: { keys: jose.JWK[] };
}

// Keep the old interface for backward compatibility during transition
interface OpenID4VPAuthorizationRequest {
  client_id: string;
  client_id_scheme: string;
  response_type: "vp_token";
  response_mode: "direct_post";
  response_uri: string;
  nonce: string;
  state: string;
  presentation_definition: unknown;
  client_metadata?: unknown;
}

interface WalletDirectPostResponse {
  vp_token: string;
  presentation_submission?: string;
  state: string;
}

interface InitTransactionRequest {
  /** DCQL query (preferred) */
  dcql_query?: DCQLQuery;
  /** Legacy presentation_definition (will be converted to DCQL) */
  presentation_definition?: unknown;
  nonce?: string;
  client_metadata?: ClientMetadata;
}

interface InitTransactionResponse {
  transaction_id: string;
  client_id: string;
  request_uri: string;
  authorization_request_uri: string;
  /** Alias for authorization_request_uri, used by same-device flow */
  deep_link_uri: string;
  expires_in: number;
}

// In-memory transaction storage (use Redis in production)
const transactions = new Map<string, OpenID4VPTransaction>();

// Transaction TTL: 5 minutes
const TRANSACTION_TTL_MS = 5 * 60 * 1000;

// Clean up expired transactions periodically
setInterval(() => {
  const now = Date.now();
  for (const [id, tx] of transactions) {
    if (tx.expiresAt < now) {
      transactions.delete(id);
      console.log(
        `[OpenID4VP] Transaction ${id.slice(0, 8)}... expired and removed`,
      );
    }
  }
}, 60000); // Check every minute

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

  // ============================================================================
  // OpenID4VP Cross-Device Flow Endpoints
  // ============================================================================

  // Initialize a new OpenID4VP transaction (returns QR code data)
  if (path === "/api/openid4vp/init" && req.method === "POST") {
    return await handleInitOpenID4VPTransaction(req, corsHeaders);
  }

  // Poll for transaction status (frontend polls this)
  if (path.startsWith("/api/openid4vp/status/") && req.method === "GET") {
    const transactionId = path.replace("/api/openid4vp/status/", "");
    return handleGetTransactionStatus(transactionId, corsHeaders);
  }

  // Wallet direct_post endpoint (wallet posts VP token here)
  if (path === "/api/openid4vp/direct_post" && req.method === "POST") {
    return await handleWalletDirectPost(req, corsHeaders);
  }

  // Get the authorization request (wallet fetches this via request_uri)
  // Note: EUDI Wallet may use either GET or POST (request_uri_method)
  // Returns a signed JWT (JAR) per RFC 9101
  if (
    path.startsWith("/api/openid4vp/request/") &&
    (req.method === "GET" || req.method === "POST")
  ) {
    const transactionId = path.replace("/api/openid4vp/request/", "");
    return await handleGetAuthorizationRequest(transactionId, corsHeaders, req);
  }

  // Public JWK Set endpoint (for JAR signature verification)
  if (path === "/api/openid4vp/.well-known/jwks.json" && req.method === "GET") {
    return await handleGetPublicJwkSet(corsHeaders);
  }

  // ============================================================================
  // Other API Endpoints
  // ============================================================================

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

// ============================================================================
// OpenID4VP Cross-Device Flow Handlers
// ============================================================================

/**
 * Serve the public JWK Set for JAR signature verification
 */
async function handleGetPublicJwkSet(
  corsHeaders: Record<string, string>,
): Promise<Response> {
  console.log("[OpenID4VP] Serving public JWK Set");

  // Export the public key
  const publicKeyJwk = { ...jarSigningKeyJwk };
  delete publicKeyJwk.d; // Remove private key component
  publicKeyJwk.kid = JAR_KEY_ID;
  publicKeyJwk.use = "sig";
  publicKeyJwk.alg = "ES256";

  const jwks = {
    keys: [publicKeyJwk],
  };

  return new Response(JSON.stringify(jwks), {
    headers: {
      "Content-Type": "application/jwk-set+json",
      ...corsHeaders,
    },
  });
}

/**
 * Initialize an OpenID4VP transaction for cross-device presentation
 * Compatible with EUDI Wallet (Android/iOS) reference implementation
 *
 * The wallet will:
 * 1. Scan the QR code containing the authorization_request_uri
 * 2. Fetch the authorization request from request_uri (returns signed JAR)
 * 3. POST the VP token to response_uri (direct_post)
 */
async function handleInitOpenID4VPTransaction(
  req: Request,
  corsHeaders: Record<string, string>,
): Promise<Response> {
  console.log("\n" + "=".repeat(60));
  console.log("[OpenID4VP] === INITIALIZING TRANSACTION ===");
  console.log("=".repeat(60));

  try {
    const body: InitTransactionRequest = await req.json();

    // Generate unique identifiers
    const transactionId = crypto.randomUUID();
    const state = crypto.randomUUID();
    const nonce = body.nonce || crypto.randomUUID();

    const now = Date.now();
    const expiresAt = now + TRANSACTION_TTL_MS;

    // Build the response_uri where wallet will POST the VP token
    const responseUri = `${PUBLIC_URL}/api/openid4vp/direct_post`;

    // Build the request_uri where wallet will fetch the full authorization request (JAR)
    const requestUri = `${PUBLIC_URL}/api/openid4vp/request/${transactionId}`;

    // Client ID using x509_san_dns scheme
    // The SAN DNS name from the leaf certificate is used as the client identifier.
    // The EUDI Wallet will verify that the JAR is signed with a certificate
    // whose SAN DNS entry matches this client_id.
    const clientId = `x509_san_dns:${jarSanDnsName}`;

    // Convert presentation_definition to DCQL query if needed, or use dcql_query directly
    let dcqlQuery: DCQLQuery;
    if (body.dcql_query) {
      dcqlQuery = body.dcql_query;
    } else if (body.presentation_definition) {
      // Convert legacy presentation_definition to DCQL
      dcqlQuery = convertPresentationDefinitionToDCQL(
        body.presentation_definition,
      );
    } else {
      // Default: request age_over_18 from EU PID
      dcqlQuery = getDefaultAgeVerificationDCQL();
    }

    // Build client metadata
    // For x509_san_dns, the wallet extracts the signing key from the x5c header,
    // so we don't need to include jwks in client_metadata.
    const clientMetadata: ClientMetadata = body.client_metadata || {
      client_name: "EwQwE Age Verification Demo",
      logo_uri: `${PUBLIC_URL}/logo.png`,
      vp_formats: {
        mso_mdoc: {
          // COSE algorithm IDs: ES256=-7, ES384=-35, ES512=-36
          issuerauth_alg_values: [-7, -35, -36],
          deviceauth_alg_values: [-7, -35, -36],
        },
      },
    };

    // Store the transaction
    const transaction: OpenID4VPTransaction = {
      id: transactionId,
      state,
      nonce,
      createdAt: now,
      expiresAt,
      status: "pending",
      dcqlQuery,
      clientId,
      responseUri,
      clientMetadata,
    };
    transactions.set(transactionId, transaction);

    console.log(
      `[OpenID4VP] Transaction created: ${transactionId.slice(0, 8)}...`,
    );
    console.log(`[OpenID4VP] State: ${state.slice(0, 8)}...`);
    console.log(`[OpenID4VP] Client ID: ${clientId}`);
    console.log(`[OpenID4VP] Response URI: ${responseUri}`);
    console.log(`[OpenID4VP] Request URI: ${requestUri}`);
    console.log(`[OpenID4VP] DCQL Query:`, JSON.stringify(dcqlQuery, null, 2));

    // Build the authorization request URI for the QR code
    // EUDI Wallet supports: openid4vp://, mdoc-openid4vp://, haip-vp://
    const authorizationRequestUri = `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(requestUri)}`;

    console.log(
      `[OpenID4VP] Authorization Request URI: ${authorizationRequestUri.slice(0, 100)}...`,
    );
    console.log("=".repeat(60) + "\n");

    const response: InitTransactionResponse = {
      transaction_id: transactionId,
      client_id: clientId,
      request_uri: requestUri,
      authorization_request_uri: authorizationRequestUri,
      // Include deep_link_uri as an alias for same-device flow
      deep_link_uri: authorizationRequestUri,
      expires_in: Math.floor(TRANSACTION_TTL_MS / 1000),
    };

    return new Response(JSON.stringify(response), {
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error) {
    console.error("[OpenID4VP] Error initializing transaction:", error);
    return new Response(
      JSON.stringify({
        error: "Failed to initialize transaction",
        message: error instanceof Error ? error.message : "Unknown error",
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      },
    );
  }
}

/**
 * Convert legacy presentation_definition to DCQL query format.
 *
 * The frontend builds paths in bracket notation: $['namespace']['claim_name']
 * For mso_mdoc DCQL, the path must be exactly [namespace, claim_name] (two plain strings).
 */
function convertPresentationDefinitionToDCQL(
  // deno-lint-ignore no-explicit-any
  presentationDefinition: any,
): DCQLQuery {
  const credentials: DCQLCredentialQuery[] = [];

  if (presentationDefinition?.input_descriptors) {
    for (const descriptor of presentationDefinition.input_descriptors) {
      // Extract doctype from descriptor format if available, otherwise fall back to EU PID
      const doctype =
        descriptor.format?.mso_mdoc?.doctype ||
        descriptor.meta?.doctype_value ||
        "eu.europa.ec.eudi.pid.1";

      const credential: DCQLCredentialQuery = {
        id: descriptor.id || crypto.randomUUID(),
        format: "mso_mdoc",
        meta: {
          doctype_value: doctype,
        },
        claims: [],
      };

      // Convert constraints.fields to claims
      if (descriptor.constraints?.fields) {
        for (const field of descriptor.constraints.fields) {
          if (field.path && field.path.length > 0) {
            const pathStr: string = field.path[0];

            // Parse the path to extract namespace and claim name.
            // Supported formats:
            //   $['namespace']['claim_name']  → bracket notation from frontend
            //   $.claim_name                  → dot notation
            //   claim_name                    → plain claim name
            const bracketMatch = pathStr.match(
              /^\$?\[['"]([^'"]+)['"]\]\[['"]([^'"]+)['"]\]$/,
            );
            if (bracketMatch) {
              // Bracket notation: $['eu.europa.ec.av.1']['age_over_18']
              // → namespace = "eu.europa.ec.av.1", claimName = "age_over_18"
              const namespace = bracketMatch[1];
              const claimName = bracketMatch[2];
              credential.claims!.push({
                path: [namespace, claimName],
              });
            } else {
              // Dot notation or plain: $.age_over_18 or age_over_18
              const claimName = pathStr.replace(/^\$\.?/, "");
              if (claimName) {
                credential.claims!.push({
                  path: [doctype, claimName],
                });
              }
            }
          }
        }
      }

      // If we extracted a namespace from bracket paths, update the doctype to match
      // (the namespace in the path is the authoritative source)
      if (credential.claims!.length > 0) {
        const firstNamespace = credential.claims![0].path[0];
        credential.meta = { doctype_value: firstNamespace };
      }

      credentials.push(credential);
    }
  }

  // If no credentials were extracted, use default
  if (credentials.length === 0) {
    return getDefaultAgeVerificationDCQL();
  }

  return { credentials };
}

/**
 * Get default DCQL query for age verification (age_over_18 from EU PID)
 */
function getDefaultAgeVerificationDCQL(): DCQLQuery {
  return {
    credentials: [
      {
        id: "eu-pid-age-verification",
        format: "mso_mdoc",
        meta: {
          doctype_value: "eu.europa.ec.eudi.pid.1",
        },
        claims: [
          {
            path: ["eu.europa.ec.eudi.pid.1", "age_over_18"],
          },
        ],
      },
    ],
  };
}

/**
 * Get the authorization request for a transaction
 * The wallet fetches this via the request_uri in the QR code
 *
 * IMPORTANT: Returns a signed JWT (JAR - JWT Secured Authorization Request) per RFC 9101
 * Content-Type: application/oauth-authz-req+jwt
 */
async function handleGetAuthorizationRequest(
  transactionId: string,
  corsHeaders: Record<string, string>,
  req: Request,
): Promise<Response> {
  console.log("\n" + "=".repeat(60));
  console.log(
    "[OpenID4VP] === WALLET FETCHING AUTHORIZATION REQUEST (JAR) ===",
  );
  console.log(`[OpenID4VP] Transaction ID: ${transactionId.slice(0, 8)}...`);
  console.log(`[OpenID4VP] Method: ${req.method}`);
  console.log(`[OpenID4VP] Accept: ${req.headers.get("accept")}`);
  console.log("=".repeat(60));

  const transaction = transactions.get(transactionId);

  if (!transaction) {
    console.log(
      `[OpenID4VP] Transaction not found: ${transactionId.slice(0, 8)}...`,
    );
    return new Response(JSON.stringify({ error: "Transaction not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  if (transaction.expiresAt < Date.now()) {
    console.log(
      `[OpenID4VP] Transaction expired: ${transactionId.slice(0, 8)}...`,
    );
    transactions.delete(transactionId);
    return new Response(JSON.stringify({ error: "Transaction expired" }), {
      status: 410,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  try {
    // Build the JWT claims for the authorization request
    const now = Math.floor(Date.now() / 1000);
    const exp = Math.floor(transaction.expiresAt / 1000);

    // Build client_metadata
    // For x509_san_dns, the wallet extracts the public key from the x5c certificate
    // chain in the JWT header, so we don't need to include jwks.
    const clientMetadata = {
      client_name:
        transaction.clientMetadata?.client_name ||
        "EwQwE Age Verification Demo",
      logo_uri:
        transaction.clientMetadata?.logo_uri || `${PUBLIC_URL}/logo.png`,
      // vp_formats_supported with COSE algorithm IDs
      vp_formats_supported: transaction.clientMetadata?.vp_formats || {
        mso_mdoc: {
          // COSE algorithm IDs: ES256=-7, ES384=-35, ES512=-36
          issuerauth_alg_values: [-7, -35, -36],
          deviceauth_alg_values: [-7, -35, -36],
        },
      },
    };

    // Build the JWT payload (authorization request claims)
    // Per OpenID4VP and EUDI Wallet expectations
    const jwtPayload: jose.JWTPayload = {
      // Standard JWT claims
      iss: transaction.clientId,
      aud: "https://self-issued.me/v2", // Self-issued OP v2
      iat: now,
      exp: exp,

      // OpenID4VP required claims
      client_id: transaction.clientId,
      client_id_scheme: "x509_san_dns",
      response_type: "vp_token",
      response_mode: "direct_post",
      response_uri: transaction.responseUri,
      state: transaction.state,
      nonce: transaction.nonce,

      // DCQL query (the credential request)
      dcql_query: transaction.dcqlQuery,

      // Client metadata
      client_metadata: clientMetadata,
    };

    console.log(`[OpenID4VP] Building JAR with claims:`);
    console.log(JSON.stringify(jwtPayload, null, 2));

    // Sign the JWT (JAR) with the x5c certificate chain in the header
    // For x509_san_dns, the wallet verifies:
    // 1. The JWT signature using the public key from the leaf certificate in x5c
    // 2. That the leaf certificate's SAN DNS matches the client_id
    // 3. The certificate chain is trusted
    const jwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader({
        alg: "ES256",
        typ: "oauth-authz-req+jwt",
        kid: JAR_KEY_ID,
        x5c: jarX5cChain,
      })
      .sign(jarSigningKey);

    console.log(
      `[OpenID4VP] Generated JAR (first 100 chars): ${jwt.slice(0, 100)}...`,
    );
    console.log("=".repeat(60) + "\n");

    // Return the signed JWT with proper content-type
    // RFC 9101: application/oauth-authz-req+jwt
    return new Response(jwt, {
      headers: {
        "Content-Type": "application/oauth-authz-req+jwt",
        ...corsHeaders,
      },
    });
  } catch (error) {
    console.error("[OpenID4VP] Error creating JAR:", error);
    return new Response(
      JSON.stringify({
        error: "Failed to create authorization request",
        message: error instanceof Error ? error.message : "Unknown error",
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      },
    );
  }
}

/**
 * Handle wallet direct_post response
 * The wallet POSTs the VP token here after user approves the presentation
 */
async function handleWalletDirectPost(
  req: Request,
  corsHeaders: Record<string, string>,
): Promise<Response> {
  console.log("\n" + "=".repeat(60));
  console.log("[OpenID4VP] === WALLET DIRECT_POST RECEIVED ===");
  console.log("=".repeat(60));

  try {
    // Log request details for debugging
    const contentType = req.headers.get("content-type") || "";
    console.log(`[OpenID4VP] Content-Type: ${contentType}`);
    console.log(`[OpenID4VP] Method: ${req.method}`);

    // Parse form data or JSON (wallets may use either)
    let vpToken: string;
    let presentationSubmission: string;
    let state: string;

    if (contentType.includes("application/x-www-form-urlencoded")) {
      const formData = await req.formData();
      vpToken = formData.get("vp_token") as string;
      presentationSubmission = formData.get(
        "presentation_submission",
      ) as string;
      state = formData.get("state") as string;
      console.log(
        `[OpenID4VP] Parsed form data - state: ${state?.slice(0, 8)}...`,
      );
    } else {
      const body = await req.json();
      vpToken = body.vp_token;
      presentationSubmission = body.presentation_submission;
      state = body.state;
      console.log(`[OpenID4VP] Parsed JSON - state: ${state?.slice(0, 8)}...`);
    }

    console.log(`[OpenID4VP] State: ${state?.slice(0, 8)}...`);
    console.log(`[OpenID4VP] VP Token length: ${vpToken?.length}`);

    // Find the transaction by state
    let transaction: OpenID4VPTransaction | undefined;
    for (const [, tx] of transactions) {
      if (tx.state === state) {
        transaction = tx;
        break;
      }
    }

    if (!transaction) {
      console.log(`[OpenID4VP] No transaction found for state: ${state}`);
      return new Response(
        JSON.stringify({ error: "Invalid state parameter" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        },
      );
    }

    console.log(
      `[OpenID4VP] Found transaction: ${transaction.id.slice(0, 8)}...`,
    );

    // Store the wallet response
    transaction.walletResponse = {
      vp_token: vpToken,
      presentation_submission: presentationSubmission,
      state,
    };
    transaction.status = "received";

    console.log(
      `[OpenID4VP] Transaction ${transaction.id.slice(0, 8)}... status -> received`,
    );
    console.log("=".repeat(60) + "\n");

    // Return success - no redirect_uri for cross-device flow
    return new Response(JSON.stringify({ status: "ok" }), {
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error) {
    console.error("[OpenID4VP] Error handling direct_post:", error);
    return new Response(
      JSON.stringify({
        error: "Failed to process wallet response",
        message: error instanceof Error ? error.message : "Unknown error",
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      },
    );
  }
}

/**
 * Get the status of a transaction (frontend polls this)
 */
function handleGetTransactionStatus(
  transactionId: string,
  corsHeaders: Record<string, string>,
): Response {
  const transaction = transactions.get(transactionId);

  if (!transaction) {
    return new Response(JSON.stringify({ error: "Transaction not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  if (transaction.expiresAt < Date.now()) {
    transactions.delete(transactionId);
    return new Response(
      JSON.stringify({
        status: "expired",
        error: "Transaction expired",
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      },
    );
  }

  // If we have a wallet response but haven't verified yet, return the response
  if (transaction.status === "received" && transaction.walletResponse) {
    return new Response(
      JSON.stringify({
        status: "received",
        vp_token: transaction.walletResponse.vp_token,
        presentation_submission:
          transaction.walletResponse.presentation_submission,
        nonce: transaction.nonce,
        state: transaction.state,
      }),
      {
        headers: { "Content-Type": "application/json", ...corsHeaders },
      },
    );
  }

  // Return current status
  return new Response(
    JSON.stringify({
      status: transaction.status,
      expires_in: Math.floor((transaction.expiresAt - Date.now()) / 1000),
    }),
    {
      headers: { "Content-Type": "application/json", ...corsHeaders },
    },
  );
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
