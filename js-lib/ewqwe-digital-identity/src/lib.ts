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
  ProfileId,
  ClientIdScheme,
  RequestFormat,
  ResponseMode,
  ProtocolProfile,
  CredentialType,
  CredentialFormat,
  ClaimDefinition,
  CredentialTypeConfig,
  OpenID4VPRequest,
  SimpleClientMetadata,
  OpenID4VPResponse,
  PresentationDefinition,
  InputDescriptor,
  ConstraintField,
  PresentationSubmission,
  DescriptorMap,
  VerifyRequest,
  VerifyResponse,
  TransactionStatus,
  WalletAuthorizationError,
  TransactionDataEntry,
  TransactionStatusResult,
  InitTransactionResponse,
  DigitalCredentialRequest,
  DigitalCredential,
  InitTransactionRequest,
} from "./types.ts";

export type {
  DCQLClaimsQuery,
  DCQLCredentialQuery,
  DCQLCredentialSetQuery,
  DCQLQuery,
} from "./dcql.ts";

export {
  EU_AV_NAMESPACE,
  EU_AV_DOCTYPE,
  ISO_MDL_NAMESPACE,
  ISO_MDL_DOCTYPE,
  EU_PID_NAMESPACE,
  EU_PID_DOCTYPE,
  buildAgeVerificationQuery,
  buildAgeVerificationQueryWithFallback,
  buildInitTransactionRequest,
  getDefaultAgeVerificationDCQL,
  determineProfile,
  generateNonce,
  parseDCQLQuery,
  extractAgeThreshold,
  buildAuthorizationRequest,
  buildCrossDeviceAuthorizationRequest,
} from "./dcql.ts";

export type { Attestation as AttestationClaims } from "./attestation.ts";
export {
  parseAttestation,
  decodeAttestation,
  getAttestationExpiryStatus,
  importVerifierPublicKey,
  verifyAttestation,
  base64urlDecode,
} from "./attestation.ts";

export { EwqweApiClient } from "./api-client.ts";
export type { ApiClientOptions, FetchFn } from "./api-client.ts";

export {
  PROTOCOL_PROFILES,
  CREDENTIAL_TYPES,
  getDefaultClaims,
  getClaimsForType,
  getProfileForType,
  getProfileIdForType,
} from "./config.ts";
