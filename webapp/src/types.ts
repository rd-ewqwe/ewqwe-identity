/**
 * Types for the Relying Party (Webapp) Application
 * Based on W3C Digital Credentials API and OpenID4VP
 */

// OpenID4VP Request types
export interface OpenID4VPRequest {
  client_id: string;
  client_id_scheme?: "redirect_uri" | "x509_san_dns" | "x509_san_uri" | "did";
  response_type: "vp_token";
  response_mode?: "direct_post" | "fragment" | "direct_post.jwt";
  nonce: string;
  presentation_definition: PresentationDefinition;
  state?: string;
  redirect_uri?: string;
  client_metadata?: ClientMetadata;
}

export interface ClientMetadata {
  client_name?: string;
  logo_uri?: string;
  client_purpose?: string;
  vp_formats?: Record<string, { alg?: string[] }>;
}

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

// OpenID4VP Response types
export interface OpenID4VPResponse {
  vp_token: string;
  presentation_submission: PresentationSubmission;
  state?: string;
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

// Credential types for display
export type CredentialType = "mdl" | "national-id" | "proof-of-age";

export interface ClaimDefinition {
  id: string;
  name: string;
  path: string;
  description?: string;
}

export interface CredentialTypeConfig {
  id: CredentialType;
  name: string;
  docType: string;
  namespace: string;
  claims: ClaimDefinition[];
}

// Verification result types
export interface VerificationResult {
  success: boolean;
  message: string;
  claims?: Record<string, unknown>;
  errors?: string[];
  verificationDetails?: {
    signatureValid: boolean;
    notExpired: boolean;
    issuerTrusted: boolean;
    timestamp: string;
  };
}

// Digital Credentials API types
export interface DigitalCredentialRequest {
  protocol: string;
  data: OpenID4VPRequest;
}

export interface DigitalCredential {
  protocol: string;
  data: OpenID4VPResponse;
}

// Extend navigator.credentials for Digital Credentials API
declare global {
  interface CredentialsContainer {
    get(options?: DigitalCredentialRequestOptions): Promise<Credential | null>;
  }

  interface DigitalCredentialRequestOptions extends CredentialRequestOptions {
    digital?: {
      requests: DigitalCredentialRequest[];
    };
  }

  interface DigitalCredentialClass {
    userAgentAllowsProtocol(protocol: string): boolean;
  }

  // eslint-disable-next-line no-var
  var DigitalCredential: DigitalCredentialClass | undefined;
}
