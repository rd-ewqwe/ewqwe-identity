/**
 * @ewqwe/digital-identity — Type Definitions
 *
 * Shared types for OpenID4VP, DCQL, credential formats, and protocol profiles.
 * Browser-compatible — no server-side APIs. Used by both front-end and back-end.
 *
 * Standards references:
 * - OpenID4VP 1.0: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 * - DCQL: OpenID4VP 1.0 §6
 * - ISO/IEC 18013-5 (mDL/mDoc)
 * - SD-JWT VC: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html
 * - EU Age Verification Profile: https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile
 */

// ============================================================================
// DCQL (Digital Credentials Query Language) — OpenID4VP 1.0 §6
// ============================================================================

/** A single claim constraint in a DCQL credential query. */
export interface DCQLClaimsQuery {
  /** Claim identifier (for referencing in claim_sets). */
  id?: string;
  /** Path to the claim — e.g. ["age_over_18"] for mso_mdoc. */
  path: string[];
  /** Namespace for mso_mdoc claims (e.g. "eu.europa.ec.av.1"). */
  namespace?: string;
  /** Expected values — if provided, claim must match one of these. */
  values?: unknown[];
  /** Whether to retain this claim after verification. */
  intent_to_retain?: boolean;
}

/**
 * A single credential query in DCQL.
 *
 * Format identifiers per the OpenID4VP 1.0 spec (Appendix B):
 * - `"mso_mdoc"` — ISO/IEC 18013-5 Mobile Documents (§B.2)
 * - `"dc+sd-jwt"` — IETF SD-JWT VC (§B.3), canonical since Nov 2024
 *   (was `"vc+sd-jwt"` before Nov 2024; both SHOULD be accepted per
 *   draft-ietf-oauth-sd-jwt-vc-08 §3.2.1)
 * - `"jwt_vc_json"` — W3C VC signed as JWT (§B.1.3.1)
 * - `"ldp_vc"` — W3C VC with Linked Data Proofs (§B.1.3.2)
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-3.2.1
 */
export interface DCQLCredentialQuery {
  /** Unique identifier for this credential query. */
  id: string;
  /**
   * Credential format identifier.
   *
   * `"dc+sd-jwt"` is the current IANA-registered identifier for SD-JWT VC
   * (application/dc+sd-jwt). The older `"vc+sd-jwt"` SHOULD also be accepted
   * during the transitional period per draft-ietf-oauth-sd-jwt-vc-08 §3.2.1.
   */
  format: "mso_mdoc" | "dc+sd-jwt" | "vc+sd-jwt" | "jwt_vc_json" | "ldp_vc";
  /** Format-specific metadata. */
  meta?: {
    /** Document type for mso_mdoc (e.g. "org.iso.18013.5.1.mDL"). */
    doctype_value?: string;
    /** Verifiable Credential Type values for dc+sd-jwt / vc+sd-jwt. */
    vct_values?: string[];
    /** Type values for jwt_vc_json / ldp_vc. */
    type_values?: string[][];
  };
  /** Claims to request from the credential. */
  claims?: DCQLClaimsQuery[];
  /** Named subsets of claims; the wallet picks one set. */
  claim_sets?: string[][];
  /** Allow the wallet to return multiple matching credentials. */
  multiple?: boolean;
  /** Require cryptographic holder binding in the presentation. */
  require_cryptographic_holder_binding?: boolean;
}

/** A credential set defining alternatives (OR logic). */
export interface DCQLCredentialSetQuery {
  /** Which credential query options satisfy this set. */
  options: string[][];
  /** Whether this credential set is required (default: true). */
  required?: boolean;
  /** Human-readable purpose for this credential set. */
  purpose?: string;
}

/** The complete DCQL query structure — OpenID4VP 1.0 §6. */
export interface DCQLQuery {
  /** Array of credential queries. */
  credentials: DCQLCredentialQuery[];
  /** Optional credential sets for defining alternatives. */
  credential_sets?: DCQLCredentialSetQuery[];
}

// ============================================================================
// Protocol Profiles
// ============================================================================

/** Protocol profile identifier. */
export type ProfileId = "haip" | "annex-a";

/** Client ID scheme (OpenID4VP 1.0 §5.9). */
export type ClientIdScheme =
  | "x509_san_dns"
  | "redirect_uri"
  | "x509_san_uri"
  | "did";

/** Authorization request format. */
export type RequestFormat = "jar" | "plain";

/** Response mode for wallet responses. */
export type ResponseMode = "direct_post" | "direct_post.jwt";

/**
 * Protocol profile configuration.
 *
 * Defines the OpenID4VP profile to use for a credential type.
 *
 * - HAIP: x509_san_dns, signed JAR, direct_post.jwt (EUDI Wallet)
 * - Annex A: redirect_uri, plain JSON, direct_post (EU AV Profile)
 */
export interface ProtocolProfile {
  id: ProfileId;
  name: string;
  description: string;
  clientIdScheme: ClientIdScheme;
  requestFormat: RequestFormat;
  responseMode: ResponseMode;
  urlSchemes: string[];
  requiresJarSigning: boolean;
}

// ============================================================================
// Credential Configuration
// ============================================================================

/** Credential type identifier. */
export type CredentialType = "mdl" | "national-id" | "proof-of-age";

/** Definition of a single claim within a credential type. */
export interface ClaimDefinition {
  id: string;
  name: string;
  path: string;
  description?: string;
}

/** Configuration for a credential type (mDL, PID, Proof of Age). */
export interface CredentialTypeConfig {
  id: CredentialType;
  name: string;
  docType: string;
  namespace: string;
  profile: ProfileId;
  claims: ClaimDefinition[];
}

// ============================================================================
// OpenID4VP Request / Response (Frontend ↔ Backend)
// ============================================================================

/**
 * OpenID4VP Authorization Request parameters.
 * Built by the frontend and sent to the backend for transaction creation.
 */
export interface OpenID4VPRequest {
  client_id: string;
  client_id_scheme?: ClientIdScheme;
  response_type: "vp_token";
  response_mode?: ResponseMode | "fragment";
  nonce: string;
  state?: string;
  redirect_uri?: string;
  presentation_definition?: PresentationDefinition;
  dcql_query?: DCQLQuery;
  client_metadata?: SimpleClientMetadata;
}

/**
 * Simplified client metadata for frontend-initiated requests.
 * The backend augments this with JWE/JWKS params for HAIP.
 */
export interface SimpleClientMetadata {
  client_name?: string;
  logo_uri?: string;
  client_purpose?: string;
  vp_formats?: Record<string, { alg?: string[] }>;
}

/**
 * Request body for `POST /api/openid4vp/init`.
 *
 * Sent by the frontend to the RP backend to initialize a new OpenID4VP
 * transaction. The backend injects `public_url` and constructs the actual
 * OpenID4VP Authorization Request delivered to the wallet.
 *
 * Replaces the former `OpenID4VPRequest & { credential_type: CredentialType }`
 * ad-hoc intersection type — now a first-class named interface matching the
 * Rust `InitTransactionRequest` struct.
 */
export interface InitTransactionRequest {
  /** DCQL query specifying the credentials to request. */
  dcql_query?: DCQLQuery;
  /** Optional nonce (auto-generated by the backend if omitted). */
  nonce?: string;
  /** RP metadata for wallet display. */
  client_metadata?: SimpleClientMetadata;
  /** Protocol profile to use: `"haip"` or `"annex-a"`. */
  profile?: ProfileId;
  /**
   * Credential type shorthand for automatic profile determination.
   * One of: `"mdl"`, `"national-id"`, `"proof-of-age"`.
   */
  credential_type?: CredentialType;
}

/** OpenID4VP Authorization Response containing the VP token. */
export interface OpenID4VPResponse {
  vp_token: string;
  presentation_submission?: PresentationSubmission | null;
  state?: string;
}

// ============================================================================
// Presentation Definition (Legacy — converted to DCQL on backend)
// ============================================================================

export interface PresentationDefinition {
  id: string;
  name?: string;
  purpose?: string;
  input_descriptors: InputDescriptor[];
}

export interface InputDescriptor {
  id: string;
  name?: string;
  purpose?: string;
  format?: {
    mso_mdoc?: { alg?: string[] };
    jwt_vp?: { alg?: string[] };
    jwt_vc?: { alg?: string[] };
    ldp_vp?: { proof_type?: string[] };
  };
  constraints: {
    limit_disclosure?: "required" | "preferred";
    fields: ConstraintField[];
  };
}

export interface ConstraintField {
  path: string[];
  id?: string;
  name?: string;
  purpose?: string;
  filter?: {
    type: string;
    const?: unknown;
    enum?: unknown[];
  };
  intent_to_retain?: boolean;
}

export interface PresentationSubmission {
  id: string;
  definition_id: string;
  descriptor_map: DescriptorMap[];
}

export interface DescriptorMap {
  id: string;
  format: string;
  path: string;
  path_nested?: {
    format: string;
    path: string;
  };
}

// ============================================================================
// Verification Results
// ============================================================================

/**
 * Response from the credential verifier backend.
 * Uses snake_case to match the Rust credential verifier's JSON output.
 */
export interface VerifyResponse {
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

// ============================================================================
// Transaction Status (Frontend polling)
// ============================================================================

/** Transaction status values. */
export type TransactionStatus =
  | "pending"
  | "received"
  | "verified"
  | "error"
  | "expired";

/** Result of polling for transaction status. */
export interface TransactionStatusResult {
  status: TransactionStatus;
  expires_in?: number;
  vp_token?: string;
  presentation_submission?: string;
  nonce?: string;
  state?: string;
}

/** Response from initializing a new OpenID4VP transaction. */
export interface InitTransactionResponse {
  transaction_id: string;
  client_id: string;
  client_id_scheme: ClientIdScheme;
  request_uri: string;
  authorization_request_uri: string;
  deep_link_uri: string;
  expires_in: number;
  profile: ProfileId;
}

// ============================================================================
// W3C Digital Credentials API types
// ============================================================================

/** Request payload for the Digital Credentials API. */
export interface DigitalCredentialRequest {
  protocol: string;
  data: OpenID4VPRequest;
}

/** Response from the Digital Credentials API. */
export interface DigitalCredential {
  protocol: string;
  data: OpenID4VPResponse;
}

/**
 * Extend navigator.credentials for the W3C Digital Credentials API.
 * @see https://www.w3.org/TR/digital-credentials/
 */
declare global {
  interface CredentialsContainer {
    get(options?: DigitalCredentialRequestOptions): Promise<Credential | null>;
  }

  interface DigitalCredentialRequestOptions extends CredentialRequestOptions {
    digital?: {
      requests: DigitalCredentialRequest[];
    };
  }

  interface DigitalCredential extends Credential {
    protocol: string;
    data: unknown;
  }

  interface DigitalCredentialClass {
    userAgentAllowsProtocol(protocol: string): boolean;
  }

  // eslint-disable-next-line no-var
  var DigitalCredential: DigitalCredentialClass | undefined;
}
