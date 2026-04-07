/**
 * EU Age Verification Wallet - Type Definitions
 *
 * Supports three credential types:
 * - Mobile Driver's License (mDL) - ISO 18013-5
 * - EU Person Identification Data (PID) - CIR 2024/2977
 * - Proof of Age (EU AV) - EU Age Verification Profile
 */

// Credential type identifiers matching ISO/EU specifications
export type CredentialType = "mdl" | "national-id" | "proof-of-age";

// ISO/EU docType and namespace mappings
export interface CredentialTypeConfig {
  docType: string;
  namespace: string;
  displayName: string;
  description: string;
  color: string; // For UI theming
}

export const CREDENTIAL_TYPE_CONFIGS: Record<
  CredentialType,
  CredentialTypeConfig
> = {
  mdl: {
    docType: "org.iso.18013.5.1.mDL",
    namespace: "org.iso.18013.5.1",
    displayName: "Mobile Driver's License",
    description: "ISO 18013-5 compliant driving license",
    color: "#2563eb", // blue
  },
  "national-id": {
    docType: "eu.europa.ec.eudi.pid.1",
    namespace: "eu.europa.ec.eudi.pid.1",
    displayName: "EU Person Identification Data",
    description: "EU Digital Identity Wallet PID",
    color: "#059669", // green
  },
  "proof-of-age": {
    docType: "eu.europa.ec.av.1",
    namespace: "eu.europa.ec.av.1",
    displayName: "Proof of Age",
    description: "EU Age Verification attestation",
    color: "#7c3aed", // purple
  },
};

/**
 * Stored Credential - represents a credential in the wallet
 */
export interface StoredCredential {
  id: string;
  type: CredentialType;
  docType: string;
  namespace: string;
  displayName: string;
  issuer: string;
  issuedAt: string; // ISO 8601
  expiresAt: string; // ISO 8601
  claims: Record<string, unknown>;
  // For demo purposes, we store a simplified representation
  // In production, this would be the actual mDoc/CBOR data
  rawCredential?: string; // Base64-encoded mDoc
}

/**
 * OpenID4VP Request structure
 */
export interface OpenID4VPRequest {
  response_type: "vp_token";
  response_mode: "direct_post";
  client_id: string;
  response_uri: string;
  nonce: string;
  state?: string;
  dcql_query: DCQLQuery;
}

/**
 * DCQL Query for credential requests
 * As specified in OpenID4VP Section 6
 */
export interface DCQLQuery {
  credentials: DCQLCredentialQuery[];
}

export interface DCQLCredentialQuery {
  id: string;
  format: "mso_mdoc" | "vc+sd-jwt";
  meta?: {
    doctype_value?: string;
  };
  claims: DCQLClaimQuery[];
}

export interface DCQLClaimQuery {
  path: string[]; // e.g., ["eu.europa.ec.av.1", "age_over_18"]
}

/**
 * OpenID4VP Response
 */
export interface OpenID4VPResponse {
  vp_token: string; // Base64url encoded DeviceResponse
  state?: string;
}

/**
 * Extension messaging types
 */
export type ExtensionMessage =
  | { type: "GET_CREDENTIALS" }
  | { type: "GET_CREDENTIAL"; id: string }
  | { type: "PRESENT_CREDENTIAL"; request: OpenID4VPRequest }
  | { type: "CREDENTIALS_UPDATED" }
  | { type: "DC_API_REQUEST"; request: DigitalCredentialRequest };

export interface DigitalCredentialRequest {
  protocol: "org-iso-mdoc" | "openid4vp-v1-unsigned";
  data: {
    deviceRequest?: string; // Base64url encoded
    encryptionInfo?: string; // Base64url encoded
    // For OpenID4VP fallback
    dcql_query?: DCQLQuery;
    nonce?: string;
  };
}

/**
 * Presentation submission for user consent
 */
export interface PresentationRequest {
  origin: string;
  credentialType: CredentialType;
  requestedClaims: string[];
  nonce: string;
  matchingCredentials: StoredCredential[];
}
