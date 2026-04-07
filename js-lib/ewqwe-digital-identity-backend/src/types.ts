/**
 * @ewqwe/digital-identity-backend — Server-Side Type Definitions
 *
 * Types and interfaces used exclusively by the OpenID4VP backend service.
 * Shared types (DCQL, VerifyResponse, etc.) are re-exported from @ewqwe/digital-identity.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 */

import type * as jose from "jose";
import type {
  DCQLQuery,
  ProfileId,
  TransactionStatus,
  VerifyResponse,
  WalletAuthorizationError,
} from "@ewqwe/digital-identity";

// ============================================================================
// Configuration
// ============================================================================

/** Configuration required to initialize the OpenID4VP service. */
export interface OpenID4VPConfig {
  /** Public URL accessible from mobile wallets (e.g., https://rp.example.com) */
  publicUrl: string;
  /** URL of the credential verifier backend (e.g., https://127.0.0.1:9443) */
  credentialVerifierUrl: string;
  /** Path to X.509 certificate chain PEM (for JAR signing) */
  x509CertPath: string;
  /** Path to private key PEM (for JAR signing) */
  x509KeyPath: string;
  /** Path to CA certificate PEM (for mTLS with credential verifier) */
  caCertPath?: string;
  /** Transaction TTL in milliseconds (default: 5 minutes) */
  transactionTtlMs?: number;
}

// ============================================================================
// Client Metadata
// ============================================================================

/**
 * Full client_metadata for authorization requests.
 *
 * This extends the simple metadata with JWE encryption parameters
 * and VP format capabilities needed for the HAIP profile.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html §5
 */
export interface ClientMetadata {
  client_name?: string;
  logo_uri?: string;
  vp_formats?: {
    mso_mdoc?: {
      alg?: string[];
      issuerauth_alg_values?: number[];
      deviceauth_alg_values?: number[];
    };
    /**
     * SD-JWT VC format capabilities.
     *
     * Uses `dc+sd-jwt` per draft-ietf-oauth-sd-jwt-vc-08 §3.2.1 (canonical identifier).
     * Verifiers SHOULD also accept `vc+sd-jwt` during the transitional period.
     */
    "dc+sd-jwt"?: {
      "sd-jwt_alg_values"?: string[];
      "kb-jwt_alg_values"?: string[];
    };
  };
  jwks?: { keys: jose.JWK[] };
  authorization_encrypted_response_alg?: string;
  authorization_encrypted_response_enc?: string;
  authorization_signed_response_alg?: string;
}

// ============================================================================
// Transaction
// ============================================================================

/**
 * OpenID4VP Authorization Response received via `direct_post` or `direct_post.jwt` (§8.2).
 *
 * When `response_type=vp_token`, the VP Token is returned in the Authorization Response.
 * With `direct_post`, the Wallet HTTP-POSTs this structure to the Verifier's `response_uri`
 * encoded as `application/x-www-form-urlencoded`.
 */
export interface DirectPostAuthorizationResponse {
  vpToken: string;
  presentationSubmission?: string;
  state: string;
}

/**
 * A complete OpenID4VP transaction, tracking lifecycle from initiation
 * through wallet response to verification.
 */
export interface OpenID4VPTransaction {
  id: string;
  state: string;
  nonce: string;
  createdAt: number;
  expiresAt: number;
  status: TransactionStatus;
  dcqlQuery: DCQLQuery;
  clientId: string;
  clientIdScheme: "x509_san_dns" | "redirect_uri";
  responseUri: string;
  responseMode: "direct_post" | "direct_post.jwt";
  profile: ProfileId;
  walletResponse?: DirectPostAuthorizationResponse;
  walletError?: WalletAuthorizationError;
  verificationResult?: VerifyResponse;
  errorMessage?: string;
  clientMetadata?: ClientMetadata;
}

// ============================================================================
// Init Transaction
// ============================================================================

/** Request body for POST /api/openid4vp/init */
export interface InitTransactionRequest {
  dcql_query?: DCQLQuery;
  /** Legacy presentation_definition (will be converted to DCQL) */
  presentation_definition?: unknown;
  nonce?: string;
  client_metadata?: ClientMetadata;
  profile?: ProfileId;
  credential_type?: string;
}

// ============================================================================
// Authorization Request Result
// ============================================================================

/** Result of building an authorization request (JAR or plain JSON). */
export interface AuthorizationRequestResult {
  /** The content body (JWT string or JSON string) */
  body: string;
  /** Content-Type header value */
  contentType: string;
}

// ============================================================================
// Verification
// ============================================================================

/** Request body for POST /api/verify — forwarded to credential verifier. */
export interface VerifyRequest {
  // deno-lint-ignore no-explicit-any
  vp_token: string | Record<string, any>;
  presentation_submission?: {
    id: string;
    definition_id: string;
    descriptor_map: Array<{
      id: string;
      format: string;
      path: string;
    }>;
  } | null;
  nonce?: string;
  state?: string;
  client_id?: string;
}

// ============================================================================
// Crypto Key Material
// ============================================================================

/** Key material for signing JWT Authorization Requests (JAR). */
export interface JarKeyMaterial {
  signingKey: jose.KeyLike;
  signingKeyJwk: jose.JWK;
  x5cChain: string[];
  sanDnsName: string;
  keyId: string;
}

/** Key material for decrypting JWE responses from wallets. */
export interface JweKeyMaterial {
  decryptionKey: CryptoKey;
  publicJwk: jose.JWK;
  keyId: string;
}

// ============================================================================
// Legacy (for backward compatibility)
// ============================================================================

/** Legacy OpenID4VP authorization request (non-DCQL). */
export interface OpenID4VPAuthorizationRequest {
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
