/**
 * DCQL (Digital Credentials Query Language) utilities for EU Age Verification.
 *
 * Re-exports all DCQL types, constants, and functions from @ewqwe/identity-front.
 *
 * @see https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 */

// Re-export type aliases for backward compatibility
export type {
  DCQLClaimsQuery as DCQLClaimQuery,
  DCQLCredentialQuery,
  DCQLCredentialSetQuery as DCQLCredentialSet,
  DCQLQuery,
} from "@ewqwe/identity-front";

// Re-export constants
export {
  EU_AV_NAMESPACE,
  EU_AV_DOCTYPE,
  ISO_MDL_NAMESPACE,
  ISO_MDL_DOCTYPE,
} from "@ewqwe/identity-front";

// Re-export query builder functions
export {
  buildAgeVerificationQuery,
  buildAgeVerificationQueryWithFallback,
  buildAuthorizationRequest,
  buildCrossDeviceAuthorizationRequest,
  generateNonce,
  parseDCQLQuery,
  extractAgeThreshold,
} from "@ewqwe/identity-front";
