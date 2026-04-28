/**
 * @ewqwe/digital-identity
 *
 * Shared types, DCQL utilities, and protocol configuration for the
 * ewqwe EU Age Verification system.
 *
 * Browser- and Node-compatible — uses Web Crypto where needed.
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
  CredentialFormat,
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
  VerifyRequest,
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
} from "./types.js";

export type {
  // DCQL types
  DCQLClaimsQuery,
  DCQLCredentialQuery,
  DCQLCredentialSetQuery,
  DCQLQuery,
} from "./dcql.js";

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
} from "./dcql.js";

// === Attestation ===
export type { Attestation as AttestationClaims } from "./attestation.js";
export {
  parseAttestation,
  decodeAttestation,
  getAttestationExpiryStatus,
  importVerifierPublicKey,
  verifyAttestation,
  base64urlDecode,
} from "./attestation.js";

// === API Client ===
export { EwqweApiClient } from "./api-client.js";
export type { ApiClientOptions, FetchFn } from "./api-client.js";

// === Config ===
export {
  PROTOCOL_PROFILES,
  CREDENTIAL_TYPES,
  getDefaultClaims,
  getClaimsForType,
  getProfileForType,
  getProfileIdForType,
} from "./config.js";
