/// <reference lib="deno.ns" />
/**
 * Tests that verify the DCQL types can represent every non-normative example
 * from OpenID4VP 1.0 Appendix D.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-D
 *
 * Run with:  deno test src/dcql_appendix_d_test.ts
 */

import { assertEquals, assertStrictEquals } from "@std/assert";
import type { DCQLQuery } from "../dcql.ts";
import { isValidDCQLQuery } from "../dcql.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Round-trip a DCQLQuery through JSON serialization and verify it is stable. */
function roundtrip(query: DCQLQuery): DCQLQuery {
  return JSON.parse(JSON.stringify(query)) as DCQLQuery;
}

/** Assert that `isValidDCQLQuery` returns `{ valid: true }` for the given query. */
function assertValid(query: DCQLQuery): void {
  const result = isValidDCQLQuery(query);
  if (result.valid !== true) {
    throw new Error(
      `Expected valid DCQL query, but got error: ${(result as { valid: false; error: string }).error}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Appendix D §1 - Single mso_mdoc credential (mVRC)
//
// Requests `vehicle_holder` from namespace `org.iso.7367.1` and
// `first_name` from namespace `org.iso.18013.5.1`.
// ---------------------------------------------------------------------------

/** The verbatim spec JSON for Appendix D, example 1. */
const APPENDIX_D1_SPEC_JSON: DCQLQuery = {
  credentials: [
    {
      id: "my_credential",
      format: "mso_mdoc",
      meta: { doctype_value: "org.iso.7367.1.mVRC" },
      claims: [
        { path: ["org.iso.7367.1", "vehicle_holder"] },
        { path: ["org.iso.18013.5.1", "first_name"] },
      ],
    },
  ],
};

Deno.test("Appendix D §1 - mVRC single mdoc: parses and is valid", () => {
  const q = APPENDIX_D1_SPEC_JSON;
  assertValid(q);
  assertStrictEquals(q.credentials.length, 1);
  assertEquals(q.credential_sets, undefined);

  const cred = q.credentials[0];
  assertStrictEquals(cred.id, "my_credential");
  assertStrictEquals(cred.format, "mso_mdoc");
  assertStrictEquals(cred.meta?.doctype_value, "org.iso.7367.1.mVRC");

  const claims = cred.claims!;
  assertStrictEquals(claims.length, 2);
  // Claims Path Pointer: [namespace, elementId] per §7.2
  assertEquals(claims[0].path, ["org.iso.7367.1", "vehicle_holder"]);
  assertEquals(claims[1].path, ["org.iso.18013.5.1", "first_name"]);
});

Deno.test("Appendix D §1 - mVRC single mdoc: round-trips through JSON", () => {
  const rt = roundtrip(APPENDIX_D1_SPEC_JSON);
  assertEquals(rt.credentials[0].claims![0].path, [
    "org.iso.7367.1",
    "vehicle_holder",
  ]);
  assertEquals(rt.credentials[0].claims![1].path, [
    "org.iso.18013.5.1",
    "first_name",
  ]);
});

// ---------------------------------------------------------------------------
// Appendix D §2 - Multiple credentials, all must be returned
//
// `pid` is dc+sd-jwt with identity claims; `mdl` is mso_mdoc.
// Without credential_sets, every credential in `credentials` must be returned.
// ---------------------------------------------------------------------------

const APPENDIX_D2_SPEC_JSON: DCQLQuery = {
  credentials: [
    {
      id: "pid",
      format: "dc+sd-jwt",
      meta: {
        vct_values: ["https://credentials.example.com/identity_credential"],
      },
      claims: [
        { path: ["given_name"] },
        { path: ["family_name"] },
        { path: ["address", "street_address"] },
      ],
    },
    {
      id: "mdl",
      format: "mso_mdoc",
      meta: { doctype_value: "org.iso.7367.1.mVRC" },
      claims: [
        { path: ["org.iso.7367.1", "vehicle_holder"] },
        { path: ["org.iso.18013.5.1", "first_name"] },
      ],
    },
  ],
};

Deno.test(
  "Appendix D §2 - multiple credentials, all required: structure",
  () => {
    const q = APPENDIX_D2_SPEC_JSON;
    assertValid(q);
    assertStrictEquals(q.credentials.length, 2);
    assertEquals(q.credential_sets, undefined); // no optional sets → all required

    const pid = q.credentials[0];
    assertStrictEquals(pid.id, "pid");
    assertStrictEquals(pid.format, "dc+sd-jwt");
    assertEquals(pid.meta?.vct_values, [
      "https://credentials.example.com/identity_credential",
    ]);
    assertEquals(pid.claims![2].path, ["address", "street_address"]);

    const mdl = q.credentials[1];
    assertStrictEquals(mdl.id, "mdl");
    assertStrictEquals(mdl.format, "mso_mdoc");
  },
);

Deno.test(
  "Appendix D §2 - multiple credentials, all required: round-trips",
  () => {
    const rt = roundtrip(APPENDIX_D2_SPEC_JSON);
    assertStrictEquals(rt.credentials.length, 2);
    assertEquals(rt.credentials[0].claims![0].path, ["given_name"]);
  },
);

// ---------------------------------------------------------------------------
// Appendix D §3 - Complex credential_sets
//
// pid OR other_pid OR (pid_reduced_cred_1 + pid_reduced_cred_2) must be
// returned; nice_to_have may optionally be returned.
// ---------------------------------------------------------------------------

const APPENDIX_D3_SPEC_JSON: DCQLQuery = {
  credentials: [
    {
      id: "pid",
      format: "dc+sd-jwt",
      meta: {
        vct_values: ["https://credentials.example.com/identity_credential"],
      },
      claims: [
        { path: ["given_name"] },
        { path: ["family_name"] },
        { path: ["address", "street_address"] },
      ],
    },
    {
      id: "other_pid",
      format: "dc+sd-jwt",
      meta: { vct_values: ["https://othercredentials.example/pid"] },
      claims: [
        { path: ["given_name"] },
        { path: ["family_name"] },
        { path: ["address", "street_address"] },
      ],
    },
    {
      id: "pid_reduced_cred_1",
      format: "dc+sd-jwt",
      meta: {
        vct_values: [
          "https://credentials.example.com/reduced_identity_credential",
        ],
      },
      claims: [{ path: ["family_name"] }, { path: ["given_name"] }],
    },
    {
      id: "pid_reduced_cred_2",
      format: "dc+sd-jwt",
      meta: { vct_values: ["https://cred.example/residence_credential"] },
      claims: [
        { path: ["postal_code"] },
        { path: ["locality"] },
        { path: ["region"] },
      ],
    },
    {
      id: "nice_to_have",
      format: "dc+sd-jwt",
      meta: { vct_values: ["https://company.example/company_rewards"] },
      claims: [{ path: ["rewards_number"] }],
    },
  ],
  credential_sets: [
    {
      options: [
        ["pid"],
        ["other_pid"],
        ["pid_reduced_cred_1", "pid_reduced_cred_2"],
      ],
    },
    {
      required: false,
      options: [["nice_to_have"]],
    },
  ],
};

Deno.test("Appendix D §3 - complex credential_sets: structure", () => {
  const q = APPENDIX_D3_SPEC_JSON;
  assertValid(q);
  assertStrictEquals(q.credentials.length, 5);

  const sets = q.credential_sets!;
  assertStrictEquals(sets.length, 2);

  // Required set (default) with three options.
  assertEquals(sets[0].required, undefined); // defaults to true per §6.2
  assertStrictEquals(sets[0].options.length, 3);
  assertEquals(sets[0].options[0], ["pid"]);
  assertEquals(sets[0].options[1], ["other_pid"]);
  assertEquals(sets[0].options[2], [
    "pid_reduced_cred_1",
    "pid_reduced_cred_2",
  ]);

  // Optional nice_to_have set.
  assertStrictEquals(sets[1].required, false);
  assertEquals(sets[1].options[0], ["nice_to_have"]);
});

Deno.test("Appendix D §3 - complex credential_sets: round-trips", () => {
  const rt = roundtrip(APPENDIX_D3_SPEC_JSON);
  assertStrictEquals(rt.credentials.length, 5);
  assertStrictEquals(rt.credential_sets!.length, 2);
  assertEquals(rt.credential_sets![1].required, false);
});

// ---------------------------------------------------------------------------
// Appendix D §4 - ID and address from either mDL or photo_card credential
//
// Either an mDL or photo_card provides the identity portion; the address is
// optional and can likewise come from either document type.
// ---------------------------------------------------------------------------

const APPENDIX_D4_SPEC_JSON: DCQLQuery = {
  credentials: [
    {
      id: "mdl-id",
      format: "mso_mdoc",
      meta: { doctype_value: "org.iso.18013.5.1.mDL" },
      claims: [
        { id: "given_name", path: ["org.iso.18013.5.1", "given_name"] },
        { id: "family_name", path: ["org.iso.18013.5.1", "family_name"] },
        { id: "portrait", path: ["org.iso.18013.5.1", "portrait"] },
      ],
    },
    {
      id: "mdl-address",
      format: "mso_mdoc",
      meta: { doctype_value: "org.iso.18013.5.1.mDL" },
      claims: [
        {
          id: "resident_address",
          path: ["org.iso.18013.5.1", "resident_address"],
        },
        {
          id: "resident_country",
          path: ["org.iso.18013.5.1", "resident_country"],
        },
      ],
    },
    {
      id: "photo_card-id",
      format: "mso_mdoc",
      meta: { doctype_value: "org.iso.23220.photoid.1" },
      claims: [
        { id: "given_name", path: ["org.iso.18013.5.1", "given_name"] },
        { id: "family_name", path: ["org.iso.18013.5.1", "family_name"] },
        { id: "portrait", path: ["org.iso.18013.5.1", "portrait"] },
      ],
    },
    {
      id: "photo_card-address",
      format: "mso_mdoc",
      meta: { doctype_value: "org.iso.23220.photoid.1" },
      claims: [
        {
          id: "resident_address",
          path: ["org.iso.18013.5.1", "resident_address"],
        },
        {
          id: "resident_country",
          path: ["org.iso.18013.5.1", "resident_country"],
        },
      ],
    },
  ],
  credential_sets: [
    {
      options: [["mdl-id"], ["photo_card-id"]],
    },
    {
      required: false,
      options: [["mdl-address"], ["photo_card-address"]],
    },
  ],
};

Deno.test("Appendix D §4 - mdl/photo_card: structure", () => {
  const q = APPENDIX_D4_SPEC_JSON;
  assertValid(q);
  assertStrictEquals(q.credentials.length, 4);

  const sets = q.credential_sets!;
  assertStrictEquals(sets.length, 2);

  // Required: mdl-id OR photo_card-id.
  assertEquals(sets[0].options, [["mdl-id"], ["photo_card-id"]]);
  // Optional: address from either document.
  assertStrictEquals(sets[1].required, false);
  assertEquals(sets[1].options, [["mdl-address"], ["photo_card-address"]]);

  // All mdoc claims use [namespace, elementId] paths (§7.2).
  const mdlIdClaims = q.credentials[0].claims!;
  assertEquals(mdlIdClaims[0].path, ["org.iso.18013.5.1", "given_name"]);
  assertStrictEquals(mdlIdClaims[0].id, "given_name");
});

Deno.test("Appendix D §4 - mdl/photo_card: round-trips", () => {
  const rt = roundtrip(APPENDIX_D4_SPEC_JSON);
  assertEquals(rt.credential_sets![0].options, [["mdl-id"], ["photo_card-id"]]);
});

// ---------------------------------------------------------------------------
// Appendix D §5 - claim_sets: mandatory + alternatives
//
// Requests `last_name` and `date_of_birth` as mandatory, plus either
// `postal_code` alone or both `locality` and `region`.
// ---------------------------------------------------------------------------

const APPENDIX_D5_SPEC_JSON: DCQLQuery = {
  credentials: [
    {
      id: "pid",
      format: "dc+sd-jwt",
      meta: {
        vct_values: ["https://credentials.example.com/identity_credential"],
      },
      claims: [
        { id: "a", path: ["last_name"] },
        { id: "b", path: ["postal_code"] },
        { id: "c", path: ["locality"] },
        { id: "d", path: ["region"] },
        { id: "e", path: ["date_of_birth"] },
      ],
      claim_sets: [
        ["a", "c", "d", "e"],
        ["a", "b", "e"],
      ],
    },
  ],
};

Deno.test("Appendix D §5 - claim_sets: structure", () => {
  const q = APPENDIX_D5_SPEC_JSON;
  assertValid(q);
  assertStrictEquals(q.credentials.length, 1);

  const cred = q.credentials[0];
  const claims = cred.claims!;
  assertStrictEquals(claims.length, 5);

  // Every claim must have an id when claim_sets is present (§6.4.1).
  for (const c of claims) {
    assertStrictEquals(
      typeof c.id,
      "string",
      `claim id missing: ${JSON.stringify(c)}`,
    );
  }

  assertEquals(claims[0].path, ["last_name"]);
  assertEquals(claims[4].path, ["date_of_birth"]);

  const cs = cred.claim_sets!;
  assertStrictEquals(cs.length, 2);
  // First option prefers data minimisation: locality+region instead of postal_code.
  assertEquals(cs[0], ["a", "c", "d", "e"]);
  // Fallback: postal_code only.
  assertEquals(cs[1], ["a", "b", "e"]);
});

Deno.test("Appendix D §5 - claim_sets: round-trips", () => {
  const rt = roundtrip(APPENDIX_D5_SPEC_JSON);
  assertEquals(rt.credentials[0].claim_sets, [
    ["a", "c", "d", "e"],
    ["a", "b", "e"],
  ]);
});

// ---------------------------------------------------------------------------
// Appendix D §6 - values constraints
//
// `last_name` must be "Doe"; `postal_code` must be "90210" or "90211".
// ---------------------------------------------------------------------------

const APPENDIX_D6_SPEC_JSON: DCQLQuery = {
  credentials: [
    {
      id: "my_credential",
      format: "dc+sd-jwt",
      meta: {
        vct_values: ["https://credentials.example.com/identity_credential"],
      },
      claims: [
        { path: ["last_name"], values: ["Doe"] },
        { path: ["first_name"] },
        { path: ["address", "street_address"] },
        { path: ["postal_code"], values: ["90210", "90211"] },
      ],
    },
  ],
};

Deno.test("Appendix D §6 - values constraints: structure", () => {
  const q = APPENDIX_D6_SPEC_JSON;
  assertValid(q);
  assertStrictEquals(q.credentials.length, 1);

  const claims = q.credentials[0].claims!;
  assertStrictEquals(claims.length, 4);

  // last_name: single allowed value.
  assertEquals(claims[0].path, ["last_name"]);
  assertEquals(claims[0].values, ["Doe"]);

  // first_name: no constraint.
  assertEquals(claims[1].path, ["first_name"]);
  assertEquals(claims[1].values, undefined);

  // address.street_address: nested path, no constraint.
  assertEquals(claims[2].path, ["address", "street_address"]);

  // postal_code: two allowed values.
  assertEquals(claims[3].path, ["postal_code"]);
  assertEquals(claims[3].values, ["90210", "90211"]);
});

Deno.test("Appendix D §6 - values constraints: round-trips", () => {
  const rt = roundtrip(APPENDIX_D6_SPEC_JSON);
  assertEquals(rt.credentials[0].claims![0].values, ["Doe"]);
  assertEquals(rt.credentials[0].claims![3].values, ["90210", "90211"]);
});
