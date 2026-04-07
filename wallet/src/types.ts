/**
 * W3C Digital Credential Types
 * Based on https://www.w3.org/TR/digital-credentials/
 */

// Verifiable Credential Data Model 2.0 types
export interface VerifiableCredential {
  "@context": string[];
  id?: string;
  type: string[];
  issuer: string | { id: string; name?: string };
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: CredentialSubject;
  proof?: Proof;
}

export interface CredentialSubject {
  id?: string;
  [key: string]: unknown;
}

export interface Proof {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
}

// Mobile Driving License (mDL) ISO 18013-5 types
export interface MobileDriverLicense {
  docType: "org.iso.18013.5.1.mDL";
  issuerSigned: {
    nameSpaces: {
      "org.iso.18013.5.1": MDLNamespace;
    };
  };
}

export interface MDLNamespace {
  family_name?: string;
  given_name?: string;
  birth_date?: string;
  portrait?: string;
  age_over_21?: boolean;
  age_over_18?: boolean;
  document_number?: string;
  issue_date?: string;
  expiry_date?: string;
  issuing_authority?: string;
  issuing_country?: string;
}

// OpenID4VP types
export interface OpenID4VPRequest {
  client_id: string;
  client_id_scheme?: string;
  response_type: "vp_token";
  response_mode?: "direct_post" | "fragment";
  nonce: string;
  presentation_definition: PresentationDefinition;
  state?: string;
  redirect_uri?: string;
}

export interface PresentationDefinition {
  id: string;
  input_descriptors: InputDescriptor[];
}

export interface InputDescriptor {
  id: string;
  name?: string;
  purpose?: string;
  format?: {
    [key: string]: { alg?: string[] };
  };
  constraints?: {
    fields?: ConstraintField[];
  };
}

export interface ConstraintField {
  path: string[];
  filter?: {
    type: string;
    const?: unknown;
    enum?: unknown[];
  };
}

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

// Digital Credentials API types (W3C)
export interface DigitalCredentialRequest {
  protocol: string;
  data: OpenID4VPRequest | Record<string, unknown>;
}

export interface DigitalCredentialResponse {
  protocol: string;
  data: OpenID4VPResponse | Record<string, unknown>;
}

// Stored credential type for the wallet
export interface StoredCredential {
  id: string;
  type: "mdl" | "national-id" | "education" | "employment" | "verifiable-credential";
  displayName: string;
  issuer: string;
  issuedAt: string;
  expiresAt?: string;
  credential: VerifiableCredential | MobileDriverLicense;
  claims: Record<string, unknown>;
}

// Attestation Provider types
export interface AttestationProvider {
  id: string;
  name: string;
  description: string;
  credentialTypes: string[];
  endpoint: string;
}
