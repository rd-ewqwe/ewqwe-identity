/**
 * @ewqwe/digital-identity
 *
 * Shared types, DCQL utilities, and protocol configuration for the
 * ewqwe EU Age Verification system.
 *
 * Browser-compatible — no server-side APIs.
 *
 * @module
 */

// === Types ===
export type {
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
  WalletAuthorizationError,
  TransactionDataEntry,
  TransactionStatusResult,
  InitTransactionResponse,
  // W3C Digital Credentials API
  DigitalCredentialRequest,
  DigitalCredential,
  // Transaction init (frontend → RP backend)
  InitTransactionRequest,
} from "./src/types.ts";

export type {
  // DCQL types
  DCQLClaimsQuery,
  DCQLCredentialQuery,
  DCQLCredentialSetQuery,
  DCQLQuery,
} from "./src/dcql.ts";

// === DCQL ===
export {
  // Constants
  EU_AV_NAMESPACE,
  EU_AV_DOCTYPE,
  ISO_MDL_NAMESPACE,
  ISO_MDL_DOCTYPE,
  EU_PID_NAMESPACE,
  EU_PID_DOCTYPE,
  // Query builders
  buildAgeVerificationQuery,
  buildAgeVerificationQueryWithFallback,
  buildInitTransactionRequest,
  getDefaultAgeVerificationDCQL,
  determineProfile,
  // Utilities
  generateNonce,
  parseDCQLQuery,
  extractAgeThreshold,
  buildAuthorizationRequest,
  buildCrossDeviceAuthorizationRequest,
} from "./src/dcql.ts";

// === Config ===
export {
  PROTOCOL_PROFILES,
  CREDENTIAL_TYPES,
  getDefaultClaims,
  getClaimsForType,
  getProfileForType,
  getProfileIdForType,
} from "./src/config.ts";
