/**
 * @ewqwe/digital-identity-backend
 *
 * Server-side OpenID4VP service for the ewqwe EU Age Verification system.
 * Handles JAR signing, JWE decryption, transaction management, and
 * credential verification delegation.
 *
 * Depends on `@ewqwe/digital-identity` for shared types and DCQL utilities.
 *
 * @module
 */

// === Re-export shared types from @ewqwe/digital-identity ===
export type {
  DCQLClaimsQuery,
  DCQLCredentialQuery,
  DCQLCredentialSetQuery,
  DCQLQuery,
  ProfileId,
  ProtocolProfile,
  TransactionStatus,
  TransactionStatusResult,
  InitTransactionResponse,
  VerifyResponse,
} from "@ewqwe/digital-identity";

// Re-export DCQL utilities consumers may need
export {
  convertPresentationDefinitionToDCQL,
  determineProfile,
  getDefaultAgeVerificationDCQL,
  generateNonce,
} from "@ewqwe/digital-identity";

// === Backend-only types ===
export type {
  OpenID4VPConfig,
  ClientMetadata,
  WalletDirectPostData,
  OpenID4VPTransaction,
  InitTransactionRequest,
  AuthorizationRequestResult,
  VerifyRequest,
  JarKeyMaterial,
  JweKeyMaterial,
  OpenID4VPAuthorizationRequest,
} from "./src/types.ts";

// === Crypto ===
export type { JarPayload, DecryptedWalletResponse } from "./src/crypto.ts";
export {
  pemToArrayBuffer,
  parsePemCertChain,
  extractSanDnsFromCert,
  initializeJarKey,
  initializeJweKey,
  signJar,
  decryptJweResponse,
  buildPublicJwkSet,
} from "./src/crypto.ts";

// === Transaction Store ===
export { TransactionStore } from "./src/transaction-store.ts";

// === OpenID4VP Service ===
export {
  OpenID4VPService,
  NotFoundError,
  ExpiredError,
  BadRequestError,
  VerifierError,
} from "./src/openid4vp-service.ts";
