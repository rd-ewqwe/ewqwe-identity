/// <reference lib="deno.ns" />
/**
 * Tests for the DCQL helper / builder functions exported from dcql.ts.
 *
 * Run with:  deno test src/dcql_helpers_test.ts
 */

import {
  assertEquals,
  assertExists,
  assertMatch,
  assertStrictEquals,
  assertThrows,
} from "@std/assert";
import {
  EU_AV_DOCTYPE,
  EU_AV_NAMESPACE,
  EU_PID_DOCTYPE,
  EU_PID_NAMESPACE,
  ISO_MDL_DOCTYPE,
  ISO_MDL_NAMESPACE,
  buildAgeVerificationQuery,
  buildAgeVerificationQueryWithFallback,
  buildAuthorizationRequest,
  buildCrossDeviceAuthorizationRequest,
  buildInitTransactionRequest,
  determineProfile,
  extractAgeThreshold,
  generateNonce,
  getDefaultAgeVerificationDCQL,
  isValidDCQLQuery,
  parseDCQLQuery,
} from "../dcql.ts";

// =============================================================================
// buildAgeVerificationQuery
// =============================================================================

Deno.test("buildAgeVerificationQuery - default threshold is 18", () => {
  const q = buildAgeVerificationQuery();
  assertStrictEquals(q.credentials.length, 1);
  const cred = q.credentials[0];
  assertStrictEquals(cred.id, "eu_av_proof");
  assertStrictEquals(cred.format, "mso_mdoc");
  assertStrictEquals(cred.meta?.doctype_value, EU_AV_DOCTYPE);
  const claim = cred.claims![0];
  assertEquals(claim.path, [EU_AV_NAMESPACE, "age_over_18"]);
  assertEquals(claim.values, [true]);
  assertStrictEquals(claim.intent_to_retain, false);
});

Deno.test("buildAgeVerificationQuery - custom threshold 21", () => {
  const q = buildAgeVerificationQuery(21);
  const claim = q.credentials[0].claims![0];
  assertEquals(claim.path, [EU_AV_NAMESPACE, "age_over_21"]);
  assertEquals(claim.values, [true]);
});

Deno.test("buildAgeVerificationQuery - produces a valid DCQL query", () => {
  const q = buildAgeVerificationQuery(18);
  const result = isValidDCQLQuery(q);
  assertStrictEquals(result.valid, true);
});

// =============================================================================
// buildAgeVerificationQueryWithFallback
// =============================================================================

Deno.test(
  "buildAgeVerificationQueryWithFallback - default threshold is 18",
  () => {
    const q = buildAgeVerificationQueryWithFallback();
    assertStrictEquals(q.credentials.length, 2);

    const [primary, fallback] = q.credentials;
    assertStrictEquals(primary.id, "eu_av_proof");
    assertStrictEquals(primary.meta?.doctype_value, EU_AV_DOCTYPE);
    assertEquals(primary.claims![0].path, [EU_AV_NAMESPACE, "age_over_18"]);

    assertStrictEquals(fallback.id, "mdl_fallback");
    assertStrictEquals(fallback.meta?.doctype_value, ISO_MDL_DOCTYPE);
    assertEquals(fallback.claims![0].path, [ISO_MDL_NAMESPACE, "age_over_18"]);
  },
);

Deno.test(
  "buildAgeVerificationQueryWithFallback - credential_sets encodes OR logic",
  () => {
    const q = buildAgeVerificationQueryWithFallback();
    assertExists(q.credential_sets);
    assertStrictEquals(q.credential_sets!.length, 1);
    const cs = q.credential_sets![0];
    assertEquals(cs.options, [["eu_av_proof"], ["mdl_fallback"]]);
    assertStrictEquals(cs.required, true);
  },
);

Deno.test("buildAgeVerificationQueryWithFallback - custom threshold 21", () => {
  const q = buildAgeVerificationQueryWithFallback(21);
  assertEquals(q.credentials[0].claims![0].path, [
    EU_AV_NAMESPACE,
    "age_over_21",
  ]);
  assertEquals(q.credentials[1].claims![0].path, [
    ISO_MDL_NAMESPACE,
    "age_over_21",
  ]);
});

Deno.test(
  "buildAgeVerificationQueryWithFallback - produces a valid DCQL query",
  () => {
    const q = buildAgeVerificationQueryWithFallback(18);
    const result = isValidDCQLQuery(q);
    assertStrictEquals(result.valid, true);
  },
);

// =============================================================================
// getDefaultAgeVerificationDCQL
// =============================================================================

Deno.test("getDefaultAgeVerificationDCQL - uses EU PID profile", () => {
  const q = getDefaultAgeVerificationDCQL();
  assertStrictEquals(q.credentials.length, 1);
  const cred = q.credentials[0];
  assertStrictEquals(cred.id, "eu-pid-age-verification");
  assertStrictEquals(cred.format, "mso_mdoc");
  assertStrictEquals(cred.meta?.doctype_value, EU_PID_DOCTYPE);
  assertEquals(cred.claims![0].path, [EU_PID_NAMESPACE, "age_over_18"]);
});

Deno.test("getDefaultAgeVerificationDCQL - produces a valid DCQL query", () => {
  const result = isValidDCQLQuery(getDefaultAgeVerificationDCQL());
  assertStrictEquals(result.valid, true);
});

// =============================================================================
// generateNonce
// =============================================================================

Deno.test("generateNonce - returns a non-empty base64url string", () => {
  const nonce = generateNonce();
  assertMatch(nonce, /^[A-Za-z0-9_-]+$/);
  // 32 random bytes → base64url without padding; minimum meaningful length
  assertStrictEquals(nonce.length > 16, true);
});

Deno.test("generateNonce - returns unique values on each call", () => {
  const a = generateNonce();
  const b = generateNonce();
  assertStrictEquals(a === b, false);
});

// =============================================================================
// parseDCQLQuery
// =============================================================================

Deno.test("parseDCQLQuery - round-trips a valid query", () => {
  const q = buildAgeVerificationQuery();
  const parsed = parseDCQLQuery(JSON.stringify(q));
  assertExists(parsed);
  assertEquals(parsed!.credentials[0].id, "eu_av_proof");
});

Deno.test("parseDCQLQuery - returns null for invalid JSON", () => {
  assertStrictEquals(parseDCQLQuery("{not valid json"), null);
});

Deno.test("parseDCQLQuery - returns null for empty string", () => {
  assertStrictEquals(parseDCQLQuery(""), null);
});

// =============================================================================
// extractAgeThreshold
// =============================================================================

Deno.test(
  "extractAgeThreshold - finds threshold in a flat dc+sd-jwt style path",
  () => {
    // For dc+sd-jwt the claim path is just ["age_over_18"] (no namespace prefix)
    const q = {
      credentials: [
        {
          id: "pid",
          format: "dc+sd-jwt" as const,
          claims: [{ path: ["age_over_18"] }],
        },
      ],
    };
    assertStrictEquals(extractAgeThreshold(q), 18);
  },
);

Deno.test("extractAgeThreshold - finds threshold 21 in flat path", () => {
  const q = {
    credentials: [
      {
        id: "pid",
        format: "dc+sd-jwt" as const,
        claims: [{ path: ["age_over_21"] }],
      },
    ],
  };
  assertStrictEquals(extractAgeThreshold(q), 21);
});

Deno.test("extractAgeThreshold - returns null for non-age claim path", () => {
  const q = {
    credentials: [
      {
        id: "mdl",
        format: "mso_mdoc" as const,
        claims: [{ path: [ISO_MDL_NAMESPACE, "family_name"] }],
      },
    ],
  };
  assertStrictEquals(extractAgeThreshold(q), null);
});

Deno.test("extractAgeThreshold - returns null for query with no claims", () => {
  const q = {
    credentials: [{ id: "x", format: "mso_mdoc" as const }],
  };
  assertStrictEquals(extractAgeThreshold(q), null);
});

// =============================================================================
// determineProfile
// =============================================================================

Deno.test("determineProfile - proof-of-age → annex-a", () => {
  assertStrictEquals(determineProfile("proof-of-age"), "annex-a");
});

Deno.test("determineProfile - mdl → haip", () => {
  assertStrictEquals(determineProfile("mdl"), "haip");
});

Deno.test("determineProfile - undefined credential type → haip", () => {
  assertStrictEquals(determineProfile(), "haip");
});

Deno.test(
  "determineProfile - explicit profile overrides credential type",
  () => {
    assertStrictEquals(determineProfile("proof-of-age", "haip"), "haip");
    assertStrictEquals(determineProfile("mdl", "annex-a"), "annex-a");
  },
);

// =============================================================================
// buildAuthorizationRequest (same-device)
// =============================================================================

Deno.test("buildAuthorizationRequest - same-device flow structure", () => {
  const params = {
    rpDomain: "rp.example.com",
    redirectUri: "https://rp.example.com/cb",
  };
  const req = buildAuthorizationRequest(params);

  assertStrictEquals(req.client_id, `redirect_uri:${params.redirectUri}`);
  assertStrictEquals(req.response_type, "vp_token");
  assertStrictEquals(req.response_mode, "fragment");
  assertStrictEquals(req.redirect_uri, params.redirectUri);
  assertExists(req.nonce);
  assertExists(req.state);
  assertExists(req.dcql_query);
});

Deno.test(
  "buildAuthorizationRequest - embeds correct default age threshold (18)",
  () => {
    const req = buildAuthorizationRequest({
      rpDomain: "rp.example.com",
      redirectUri: "https://rp.example.com/cb",
    });
    const query = JSON.parse(req.dcql_query);
    assertEquals(query.credentials[0].claims[0].path, [
      EU_AV_NAMESPACE,
      "age_over_18",
    ]);
  },
);

Deno.test("buildAuthorizationRequest - embeds custom age threshold", () => {
  const req = buildAuthorizationRequest({
    rpDomain: "rp.example.com",
    redirectUri: "https://rp.example.com/cb",
    ageThreshold: 21,
  });
  const query = JSON.parse(req.dcql_query);
  assertEquals(query.credentials[0].claims[0].path, [
    EU_AV_NAMESPACE,
    "age_over_21",
  ]);
});

Deno.test("buildAuthorizationRequest - accepts pre-set nonce and state", () => {
  const req = buildAuthorizationRequest({
    rpDomain: "rp.example.com",
    redirectUri: "https://rp.example.com/cb",
    nonce: "my-nonce",
    state: "my-state",
  });
  assertStrictEquals(req.nonce, "my-nonce");
  assertStrictEquals(req.state, "my-state");
});

// =============================================================================
// buildCrossDeviceAuthorizationRequest (cross-device)
// =============================================================================

Deno.test(
  "buildCrossDeviceAuthorizationRequest - cross-device flow structure",
  () => {
    const params = {
      rpDomain: "rp.example.com",
      responseUri: "https://rp.example.com/direct_post",
    };
    const req = buildCrossDeviceAuthorizationRequest(params);

    assertStrictEquals(req.client_id, `x509_san_dns:${params.rpDomain}`);
    assertStrictEquals(req.response_type, "vp_token");
    assertStrictEquals(req.response_mode, "direct_post");
    assertStrictEquals(req.response_uri, params.responseUri);
    assertExists(req.nonce);
    assertExists(req.state);
    assertExists(req.dcql_query);
  },
);

Deno.test(
  "buildCrossDeviceAuthorizationRequest - uses fallback query (two credentials)",
  () => {
    const req = buildCrossDeviceAuthorizationRequest({
      rpDomain: "rp.example.com",
      responseUri: "https://rp.example.com/direct_post",
    });
    const query = JSON.parse(req.dcql_query);
    assertStrictEquals(query.credentials.length, 2);
    assertExists(query.credential_sets);
  },
);

Deno.test(
  "buildCrossDeviceAuthorizationRequest - accepts pre-set nonce and state",
  () => {
    const req = buildCrossDeviceAuthorizationRequest({
      rpDomain: "rp.example.com",
      responseUri: "https://rp.example.com/direct_post",
      nonce: "fixed-nonce",
      state: "fixed-state",
    });
    assertStrictEquals(req.nonce, "fixed-nonce");
    assertStrictEquals(req.state, "fixed-state");
  },
);

// =============================================================================
// buildInitTransactionRequest
// =============================================================================

Deno.test(
  "buildInitTransactionRequest - builds request for proof-of-age",
  () => {
    const req = buildInitTransactionRequest(
      "https://webapp.example.com",
      "proof-of-age",
      ["age_over_18"],
    );
    assertStrictEquals(req.public_url, "https://webapp.example.com");
    assertStrictEquals(req.credential_type, "proof-of-age");
    assertExists(req.nonce);
    assertExists(req.dcql_query);
    const dcql = req.dcql_query!;
    assertStrictEquals(dcql.credentials.length, 1);
    const cred = dcql.credentials[0];
    assertStrictEquals(cred.id, "proof-of-age_credential");
    assertStrictEquals(cred.format, "mso_mdoc");
    // Claims path should be [namespace, claimId]
    assertExists(cred.claims);
    assertStrictEquals(cred.claims![0].id, "age_over_18");
    assertStrictEquals(cred.claims![0].path[1], "age_over_18");
  },
);

Deno.test(
  "buildInitTransactionRequest - throws for unknown credential type",
  () => {
    assertThrows(
      () =>
        buildInitTransactionRequest("https://example.com", "unknown" as never, [
          "foo",
        ]),
      Error,
      "Unknown credential type",
    );
  },
);

// =============================================================================
// isValidDCQLQuery - invalid cases
// =============================================================================

Deno.test("isValidDCQLQuery - rejects empty credentials array", () => {
  const result = isValidDCQLQuery({ credentials: [] });
  assertStrictEquals(result.valid, false);
});

Deno.test("isValidDCQLQuery - rejects duplicate credential ids", () => {
  const result = isValidDCQLQuery({
    credentials: [
      { id: "a", format: "mso_mdoc" },
      { id: "a", format: "mso_mdoc" },
    ],
  });
  assertStrictEquals(result.valid, false);
});

Deno.test(
  "isValidDCQLQuery - rejects credential id with invalid characters",
  () => {
    const result = isValidDCQLQuery({
      credentials: [{ id: "has space", format: "mso_mdoc" }],
    });
    assertStrictEquals(result.valid, false);
  },
);

Deno.test("isValidDCQLQuery - rejects empty trusted_authorities", () => {
  const result = isValidDCQLQuery({
    credentials: [
      {
        id: "c1",
        format: "mso_mdoc",
        trusted_authorities: [],
      },
    ],
  });
  assertStrictEquals(result.valid, false);
});

Deno.test("isValidDCQLQuery - rejects claim_sets without claims", () => {
  const result = isValidDCQLQuery({
    credentials: [
      {
        id: "c1",
        format: "mso_mdoc",
        claim_sets: [["x"]],
      },
    ],
  });
  assertStrictEquals(result.valid, false);
});

Deno.test(
  "isValidDCQLQuery - rejects claim_sets referencing unknown claim id",
  () => {
    const result = isValidDCQLQuery({
      credentials: [
        {
          id: "c1",
          format: "mso_mdoc",
          claims: [{ id: "known", path: ["foo"] }],
          claim_sets: [["unknown_id"]],
        },
      ],
    });
    assertStrictEquals(result.valid, false);
  },
);

Deno.test(
  "isValidDCQLQuery - rejects credential_sets referencing unknown credential id",
  () => {
    const result = isValidDCQLQuery({
      credentials: [{ id: "c1", format: "mso_mdoc" }],
      credential_sets: [{ options: [["c1"], ["nonexistent"]] }],
    });
    assertStrictEquals(result.valid, false);
  },
);
