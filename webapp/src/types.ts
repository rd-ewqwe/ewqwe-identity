/**
 * Types for the Relying Party (Webapp) Application
 *
 * Re-exports all shared types from @ewqwe/identity-front.
 * Webapp-specific type aliases are defined here for convenience.
 */
export type {
  // DCQL types
  DCQLClaimsQuery,
  DCQLCredentialQuery,
  DCQLCredentialSetQuery,
  DCQLQuery,
  // Protocol profiles
  ProfileId,
  ClientIdScheme,
  RequestFormat,
  ResponseMode,
  ProtocolProfile,
  // Credential configuration
  CredentialType,
  ClaimDefinition,
  CredentialTypeConfig,
  // OpenID4VP
  OpenID4VPRequest,
  SimpleClientMetadata,
  OpenID4VPResponse,
  // Legacy Presentation Definition format
  PresentationDefinition,
  InputDescriptor,
  ConstraintField,
  PresentationSubmission,
  DescriptorMap,
  // Verification
  VerifyResponse,
  TransactionStatus,
  TransactionStatusResult,
  InitTransactionResponse,
  // W3C Digital Credentials API
  DigitalCredentialRequest,
  DigitalCredential,
} from "@ewqwe/identity-front";

import type { VerifyResponse } from "@ewqwe/identity-front";

/**
 * Alias for backward compatibility.
 * @deprecated Use `VerifyResponse` directly.
 */
export type VerificationResult = VerifyResponse;
