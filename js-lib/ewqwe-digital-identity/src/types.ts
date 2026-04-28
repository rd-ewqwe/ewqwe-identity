/**
 * @ewqwe/digital-identity — Type Definitions
 *
 * Shared types for OpenID4VP, DCQL, credential formats, and protocol profiles.
 * Node.js compatible — no platform-specific APIs. Used by both front-end and back-end.
 *
 * Standards references:
 * - OpenID4VP 1.0: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 * - DCQL: OpenID4VP 1.0 §6
 * - ISO/IEC 18013-5 (mDL/mDoc)
 * - SD-JWT VC: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html
 * - EU Age Verification Profile: https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile
 */

import type { DCQLQuery } from "./dcql.js";

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
  | "did"
  | "x509_hash";

/** Authorization request format. */
export type RequestFormat = "jar" | "plain";

/**
 * Response mode for wallet responses (OpenID4VP 1.0 §5.2, Appendix A.2).
 *
 * | Value            | Description                                                       |
 * |------------------|-------------------------------------------------------------------|
 * | `fragment`       | Default for `vp_token`; response in redirect URL fragment (same-device) |
 * | `direct_post`    | Wallet POSTs response to `response_uri` (cross-device)            |
 * | `direct_post.jwt`| Like `direct_post` but response is encrypted JWE (HAIP mandatory) |
 * | `dc_api`         | Response via W3C Digital Credentials API, unencrypted             |
 * | `dc_api.jwt`     | Response via W3C DC API, encrypted JWE (Appendix A §8.3)          |
 */
export type ResponseMode =
  | "fragment"
  | "direct_post"
  | "direct_post.jwt"
  | "dc_api"
  | "dc_api.jwt";

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
export type CredentialType =
  | "mdl"
  | "national-id"
  | "national-id-sd-jwt"
  | "proof-of-age"
  | "photo-id"
  | "tax"
  | "tax-sd-jwt"
  | "pseudonym-age"
  | "pseudonym-age-sd-jwt"
  | "ehic"
  | "ehic-sd-jwt"
  | "health-id"
  | "health-id-sd-jwt"
  | "iban"
  | "iban-sd-jwt"
  | "loyalty"
  | "msisdn"
  | "msisdn-sd-jwt"
  | "pda1"
  | "pda1-sd-jwt"
  | "por"
  | "por-sd-jwt"
  | "reservation"
  | "cor";

/** Credential format identifier used in DCQL queries. */
export type CredentialFormat = "mso_mdoc" | "dc+sd-jwt";

/** Definition of a single claim within a credential type. */
export interface ClaimDefinition {
  id: string;
  name: string;
  description?: string;
}

/** Configuration for a credential type (mDL, PID, Proof of Age, etc.). */
export interface CredentialTypeConfig {
  id: CredentialType;
  name: string;
  /**
   * Credential format identifier for DCQL queries.
   * - `"mso_mdoc"` — ISO/IEC 18013-5 Mobile Documents (CBOR-encoded)
   * - `"dc+sd-jwt"` — IETF SD-JWT Verifiable Credentials (JSON-encoded)
   */
  format: CredentialFormat;
  /** Document type for mso_mdoc credentials (e.g. `"org.iso.18013.5.1.mDL"`). */
  docType: string;
  /** Namespace for mso_mdoc claims (e.g. `"org.iso.18013.5.1"`). */
  namespace: string;
  /** Verifiable Credential Type for dc+sd-jwt credentials (e.g. `"urn:eudi:pid:1"`). */
  vct?: string;
  profile: ProfileId;
  claims: ClaimDefinition[];
}

// ============================================================================
// OpenID4VP Request / Response (Frontend ↔ Backend)
// ============================================================================

/**
 * OpenID4VP 1.0 Authorization Request parameters.
 *
 * Built by the frontend and sent to the backend for transaction creation.
 * The backend injects server-side fields (`response_uri`, `request_uri`, JAR
 * signing, JWKS for encrypted responses) before forwarding to the wallet.
 *
 * **Key spec constraints (OpenID4VP 1.0 §5)**:
 * - `dcql_query` MUST be present (either directly or via `scope`); it is the
 *   only credential-query mechanism in OpenID4VP 1.0.  The legacy DIF
 *   Presentation Exchange parameter `presentation_definition` **does not exist**
 *   in OpenID4VP 1.0 and MUST NOT be sent.
 * - `response_mode` is REQUIRED per §5.2; defaults to `fragment` when omitted.
 * - When `response_mode` is `direct_post`/`direct_post.jwt`, use `response_uri`
 *   (not `redirect_uri`) — the two MUST NOT coexist (§8.2).
 * - For the W3C Digital Credentials API flow use `dc_api` / `dc_api.jwt`
 *   (Appendix A.2); `state` is ignored by DC API.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5
 */
export interface OpenID4VPRequest {
  /** REQUIRED. Client Identifier of the Verifier (§5.2). */
  client_id: string;
  /**
   * Client Identifier Prefix — tells the wallet how to validate the client_id
   * (§5.9). The prefix is prepended to `client_id` with a `:` separator on
   * the wire (e.g. `x509_san_dns:rp.example.com`).
   */
  client_id_scheme?: ClientIdScheme;

  /** REQUIRED. Must be `"vp_token"` for VP-only requests (§5.6). */
  response_type: "vp_token";

  /**
   * REQUIRED. How the wallet returns the Authorization Response (§5.2).
   * Defaults to `"fragment"` when absent.
   */
  response_mode?: ResponseMode;

  /** REQUIRED. Fresh, random nonce binding the presentation to this request (§5.2). */
  nonce: string;

  /**
   * REQUIRED when no Holder Binding proof is requested (§5.3), recommended
   * otherwise for session fixation protection (§14.2).
   */
  state?: string;

  /**
   * Redirect URI for `fragment` / `query` response modes.
   * MUST NOT be present when `response_mode` is `direct_post` or
   * `direct_post.jwt` — use `response_uri` instead (§8.2).
   */
  redirect_uri?: string;

  /**
   * DCQL credential query (§6, §5.1).
   *
   * This is the **only** credential-query parameter in OpenID4VP 1.0.
   * Either `dcql_query` or a `scope` referencing a DCQL query MUST be
   * present, but not both.
   */
  dcql_query?: DCQLQuery;

  /** Verifier metadata forwarded to the wallet (§5.1). */
  client_metadata?: SimpleClientMetadata;
}

/**
 * OpenID4VP 1.0 Authorization Response (§8.1 / §8.2).
 *
 * Represents the wallet's Authorization Response in all transport variants:
 * - **`direct_post`** (cross-device): wallet HTTP-POSTs form data to `response_uri`.
 * - **`fragment`** / **`dc_api`** (same-device / W3C DC API): response returned inline.
 *
 * **`vp_token` structure with DCQL (§8.1)**:
 * A JSON-encoded `Record<credentialQueryId, presentation[]>` — each key is the
 * `id` of a Credential Query from the DCQL request and the value is an array of
 * base64url-encoded credential presentations:
 * ```json
 * { "my_mdl": ["<base64url-DeviceResponse>"] }
 * ```
 *
 * **`presentation_submission`**: DIF Presentation Exchange field — **absent in
 * OpenID4VP 1.0 DCQL responses**.  Kept for backward-compatibility with wallets
 * still on older drafts.  May arrive as a raw JSON **string** (wire format from
 * `direct_post`) or as a parsed {@link PresentationSubmission} object (after
 * processing by the backend).
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1
 */
export interface OpenID4VPResponse {
  /**
   * JSON-encoded `Record<credentialQueryId, presentation[]>` (§8.1).
   * Parse with `JSON.parse()` to obtain the credential ID → presentations mapping.
   */
  vp_token: string;

  /**
   * @deprecated Not part of OpenID4VP 1.0 DCQL responses.
   * Only present for backward-compatibility with wallets using the legacy
   * DIF Presentation Exchange format.  Will be absent in all spec-compliant
   * responses.  May be a raw JSON string (wire) or a parsed object.
   */
  presentation_submission?: string | PresentationSubmission;

  /** Echoes the `state` from the Authorization Request (§8.2). */
  state?: string;
}

// ============================================================================
// VP Format Capabilities (vp_formats / vp_formats_supported)
// ============================================================================

/**
 * Per-format parameters for **ISO/IEC 18013-5 mDoc** (`mso_mdoc`).
 *
 * Algorithm identifiers are **COSE integer IDs** (RFC 8152 / IANA COSE Algorithms):
 * - `-7`  → ES256 (ECDSA P-256 + SHA-256)  — HAIP mandatory
 * - `-35` → ES384 (ECDSA P-384 + SHA-384)
 * - `-36` → ES512 (ECDSA P-521 + SHA-512)
 * - `-8`  → EdDSA
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.2
 */
export interface MsoMdocVpFormat {
  /** COSE algorithm IDs accepted for the IssuerAuth `COSE_Sign1` structure. */
  issuerauth_alg_values?: number[];
  /** COSE algorithm IDs accepted for DeviceSignature or DeviceMac. */
  deviceauth_alg_values?: number[];
}

/**
 * Per-format parameters for **IETF SD-JWT VC** (`dc+sd-jwt` / `vc+sd-jwt`).
 *
 * Algorithm identifiers use JOSE string names and MUST be fully-specified
 * per draft-ietf-jose-fully-specified-algorithms.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.4
 */
export interface SdJwtVcVpFormat {
  /** JOSE algorithm identifiers for the Issuer-signed SD-JWT (`alg` JOSE header). */
  "sd-jwt_alg_values"?: string[];
  /** JOSE algorithm identifiers for the Key Binding JWT (`alg` JOSE header). */
  "kb-jwt_alg_values"?: string[];
}

/**
 * Per-format parameters for **W3C VC signed as JWT** (`jwt_vc_json`).
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1.3.1.3
 */
export interface JwtVcJsonVpFormat {
  /** JOSE algorithm identifiers for the Verifiable Credential / Presentation
   * (`alg` JWS header, RFC 7515). */
  alg_values?: string[];
}

/**
 * Per-format parameters for **W3C VC with Linked Data Proofs** (`ldp_vc`).
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1.3.2.3
 */
export interface LdpVcVpFormat {
  /** Data Integrity proof type identifiers (e.g. `"DataIntegrityProof"`). */
  proof_type_values?: string[];
  /** Cryptosuite identifiers when proof type includes `"DataIntegrityProof"`
   * (e.g. `"ecdsa-rdfc-2019"`, `"bbs-2023"`). */
  cryptosuite_values?: string[];
}

/**
 * VP format capabilities included in `client_metadata`.
 *
 * Each field corresponds to a **Credential Format Identifier** (a fixed enumeration
 * per OpenID4VP 1.0 §11.1 and Appendix B).  The server re-keys this object from
 * `vp_formats` (request body) to `vp_formats_supported` (wallet wire format).
 *
 * Format identifiers: `mso_mdoc`, `dc+sd-jwt`, `vc+sd-jwt`, `jwt_vc_json`, `ldp_vc`.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-11.1
 */
export interface VpFormats {
  /**
   * ISO/IEC 18013-5 Mobile Documents (§B.2).
   * Algorithm IDs use COSE integers (RFC 8152).
   */
  mso_mdoc?: MsoMdocVpFormat;
  /**
   * IETF SD-JWT VC — current IANA-registered identifier, canonical since Nov 2024 (§B.3).
   * Algorithm IDs use JOSE strings.
   */
  "dc+sd-jwt"?: SdJwtVcVpFormat;
  /**
   * IETF SD-JWT VC — legacy identifier, superseded by `dc+sd-jwt` (§B.3).
   * Both SHOULD be accepted during the transitional period per
   * draft-ietf-oauth-sd-jwt-vc-08 §3.2.1.
   */
  "vc+sd-jwt"?: SdJwtVcVpFormat;
  /** W3C VC signed as JWT, without JSON-LD (§B.1.3.1). */
  jwt_vc_json?: JwtVcJsonVpFormat;
  /** W3C VC with Linked Data / Data Integrity Proofs (§B.1.3.2). */
  ldp_vc?: LdpVcVpFormat;
}

/**
 * Simplified client metadata for frontend-initiated requests.
 *
 * The backend augments this with JWE/JWKS params for HAIP:
 * - `jwks`: ephemeral P-256 key for response encryption (generated per request)
 * - `authorization_encrypted_response_alg`: `"ECDH-ES"` (fixed, HAIP §5 mandates P-256)
 * - `authorization_encrypted_response_enc`: `"A256GCM"` (server default; OpenID4VP §8.3
 *   default is `A128GCM` but the server uses `A256GCM` for stronger 256-bit encryption)
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9
 */
export interface SimpleClientMetadata {
  /** Wallet-facing display name for the Relying Party (RFC 7591 `client_name`). */
  client_name?: string;
  /** Wallet-facing logo URI for the Relying Party (RFC 7591 `logo_uri`). */
  logo_uri?: string;
  /**
   * Credential format capabilities (OpenID4VP §11.1, Appendix B).
   * Re-keyed to `vp_formats_supported` by the server before sending to the wallet.
   */
  vp_formats?: VpFormats;
}

/**
 * Request body for `POST /ewqwe_api/openid4vp/init`.
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
  /** **Required**: The RP's public URL that the wallet will interact with.
   * Used to construct `response_uri` and `request_uri` in the OpenID4VP flow. */
  public_url: string;

  /** DCQL query specifying the credentials to request. */
  dcql_query?: DCQLQuery;

  /** Optional nonce (auto-generated by the backend if omitted). */
  nonce?: string;

  /** Optional OAuth/OpenID4VP state value maintained by the client. */
  state?: string;

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

export interface InitTransactionResponse {
  /** Unique transaction ID for polling status. */
  transaction_id: string;

  /** Constructed client_id. */
  client_id: string;

  /** Client ID scheme used. */
  client_id_scheme: ClientIdScheme;

  /** URI where wallet fetches the authorization request. */
  request_uri: string;

  /** Full authorization request URI for QR code / deep link. */
  authorization_request_uri: string;

  /** Seconds until transaction expires. */
  expires_in: number;

  /** Selected protocol profile. */
  profile: ProfileId;

  /**
   * QR code as a `data:image/svg+xml;base64,...` data URL.
   * Only present for cross-device flows — assign directly to `<img src>`.
   */
  qr_code_data_url?: string;
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
// Verification
// ============================================================================

/**
 * Request to verify a verifiable presentation (VP) token.
 */
export interface VerifyRequest {
  vp_token: string;
  presentation_submission?: string | PresentationSubmission;
  state?: string;
  client_id?: string;
}

/**
 * Response from the credential verifier backend.
 * Uses snake_case to match the Rust credential verifier's JSON output.
 */
export interface VerifyResponse {
  success: boolean;
  message: string;
  verification_details?: {
    signature_valid: boolean;
    not_expired: boolean;
    issuer_trusted: boolean;
  };
  /** Signed attestation JWT — always present (contains `verified`, `doc_type`, and credential claims). */
  attestation: string;
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

/**
 * A decoded entry from the `transaction_data` Authorization Request parameter (§8.4).
 *
 * The Authorization Request MAY include `transaction_data` — a non-empty array of
 * base64url-encoded JSON objects, each describing a transaction the wallet is asked
 * to authorise (e.g. a payment, consent, or contract signing).
 *
 * The wallet MUST bind these into its credential presentations:
 * - **SD-JWT VC**: via `transaction_data_hashes` in the Key Binding JWT (§B.3.3.1).
 * - **mdoc**: via the `DeviceSigned` structure (§B.2.1).
 *
 * The credential verifier echoes the raw `transaction_data` strings back to the RP
 * in {@link TransactionStatusResult} so it can verify the hashes.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4
 */
export interface TransactionDataEntry {
  /** Transaction data type identifier (REQUIRED per §8.4). */
  type: string;
  /**
   * DCQL Credential Query IDs that can authorise this transaction data entry
   * (REQUIRED per §8.4).
   */
  credential_ids: string[];
  /**
   * Hash algorithm(s) the RP accepts for `transaction_data_hashes` in the
   * SD-JWT VC Key Binding JWT (§B.3.3.1, OPTIONAL).
   *
   * Values are string identifiers from the
   * [IANA Named Information Hash Algorithm registry](https://www.iana.org/assignments/named-information/named-information.xhtml)
   * (e.g. `"sha-256"`, `"sha-384"`).
   * When absent the wallet MUST use `"sha-256"` (the default).
   * Only meaningful for `dc+sd-jwt` credential formats.
   */
  transaction_data_hashes_alg?: string[];
  /** Type-specific parameters (arbitrary extra fields defined by the `type` schema). */
  [key: string]: unknown;
}

/** Result of polling for transaction status. */
export interface TransactionStatusResult {
  /** Current transaction status. */
  status: TransactionStatus;

  /** Seconds until the transaction expires. Present when `status === "pending"`. */
  expires_in?: number;

  /**
   * The Authorization Response received from the wallet (OpenID4VP 1.0 §8.1 + §8.2).
   * Only present when `status === "received"`.
   */
  authorization_response?: OpenID4VPResponse;

  /**
   * The `nonce` from the original Authorization Request (§5.2).
   * Present when `status === "received"`, needed for VP Token replay validation (§14.1).
   */
  nonce?: string;

  /**
   * Error response sent by the Wallet (§8.5). Present when `status === "error"`
   * and the error originated from the wallet (not an internal server error).
   */
  wallet_error?: WalletAuthorizationError;

  error_message?: string;

  /**
   * The original `transaction_data` entries from the Authorization Request (§8.4).
   * Present when `status === "received"` so the RP can verify the hashes that the
   * wallet embedded in its credential presentations.
   *
   * Each element is a base64url-encoded JSON string (as sent in the auth request).
   */
  transaction_data?: string[];
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
 * Error response sent by the Wallet to the Verifier's `response_uri` (§8.5).
 *
 * Instead of a VP Token the Wallet sends this when it cannot or will not fulfil
 * the Authorization Request. Field names are snake_case to match Rust API JSON.
 *
 * Error codes:
 * - `invalid_request` — malformed / unsupported request parameters
 * - `access_denied` — no matching credentials, user denied consent, or auth failed
 * - `vp_formats_not_supported` — no supported VP format found
 * - `invalid_request_uri_method` — unsupported `request_uri_method` value
 * - `invalid_transaction_data` — `transaction_data` claim issue
 * - `wallet_unavailable` — wallet cannot be invoked (§15.9.1)
 */
export interface WalletAuthorizationError {
  /** Error code from §8.5 (e.g. `"access_denied"`). */
  error: string;
  /** Human-readable error description (optional). */
  error_description?: string;
  /** The `state` parameter echoed back from the Authorization Request. */
  state?: string;
}
