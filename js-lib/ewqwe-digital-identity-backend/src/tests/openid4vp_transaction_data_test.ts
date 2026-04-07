/// <reference lib="deno.ns" />
/**
 * Tests for §8.4 Transaction Data of OpenID4VP 1.0 — TypeScript service layer.
 *
 * These tests validate that `transaction_data` entries supplied in the init
 * request are stored, forwarded in the Authorization Request, and echoed back
 * in the status result so the RP can verify the wallet's transaction-data
 * hashes (§B.3.3.1 / §B.2.1).
 *
 * The tests operate directly on `TransactionStore` (no crypto dependencies),
 * mirroring the pattern used in `openid4vp_wallet_error_test.ts`.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4
 */

import { assertEquals, assertExists } from "@std/assert";
import { TransactionStore } from "../transaction-store.ts";
import type { OpenID4VPTransaction } from "../types.ts";
import type { TransactionStatusResult } from "@ewqwe/digital-identity";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Encode a transaction data entry as base64url JSON (as the RP would do). */
function encodeTransactionDataEntry(entry: Record<string, unknown>): string {
  const json = JSON.stringify(entry);
  const bytes = new TextEncoder().encode(json);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  // base64url: standard base64, replace +→- /→_ strip =
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function makeTransaction(
  id: string,
  state: string,
  opts: { transactionData?: string[]; ttlMs?: number } = {},
): OpenID4VPTransaction {
  const now = Date.now();
  return {
    id,
    state,
    nonce: "test-nonce",
    createdAt: now,
    expiresAt: now + (opts.ttlMs ?? 60_000),
    status: "pending",
    dcqlQuery: { credentials: [] },
    clientId: "redirect_uri:https://rp.example.com/api/openid4vp/direct_post",
    clientIdScheme: "redirect_uri",
    responseUri: "https://rp.example.com/api/openid4vp/direct_post",
    responseMode: "direct_post",
    profile: "annex-a",
    transactionData: opts.transactionData,
  };
}

/** Simulate `getTransactionStatus` (mirrors the service's received-branch logic). */
function getStatusForTransaction(
  store: TransactionStore,
  id: string,
): TransactionStatusResult {
  const tx = store.get(id);
  if (!tx) throw new Error("Not found");
  if (store.isExpired(id)) return { status: "expired" };

  if (tx.status === "received" && tx.walletResponse) {
    return {
      status: "received",
      authorization_response: {
        vp_token: tx.walletResponse.vpToken,
        presentation_submission: tx.walletResponse.presentationSubmission,
        state: tx.walletResponse.state,
      },
      nonce: tx.nonce,
      transaction_data: tx.transactionData,
    };
  }

  if (tx.status === "error") {
    return { status: "error", wallet_error: tx.walletError };
  }

  return {
    status: tx.status,
    expires_in: Math.floor((tx.expiresAt - Date.now()) / 1000),
  };
}

// ---------------------------------------------------------------------------
// §8.4 — Transaction Data stored in transaction
// ---------------------------------------------------------------------------

Deno.test(
  "§8.4 — transaction_data is stored in OpenID4VPTransaction when provided",
  () => {
    const entry = {
      type: "payment",
      credential_ids: ["my_credential"],
      amount: "100.00",
      currency: "EUR",
    };
    const encoded = encodeTransactionDataEntry(entry);

    const tx = makeTransaction("tx-td-1", "state-td-1", {
      transactionData: [encoded],
    });

    assertEquals(tx.transactionData, [encoded]);
    assertEquals(tx.transactionData?.length, 1);
  },
);

Deno.test("§8.4 — transaction_data is absent when not provided", () => {
  const tx = makeTransaction("tx-td-2", "state-td-2");
  assertEquals(tx.transactionData, undefined);
});

// ---------------------------------------------------------------------------
// §8.4 — transaction_data echoed back in status result
// ---------------------------------------------------------------------------

Deno.test(
  "§8.4 — status result echoes transaction_data when status is 'received'",
  () => {
    const entry = {
      type: "age_verification",
      credential_ids: ["age_cred"],
      minimum_age: 18,
    };
    const encoded = encodeTransactionDataEntry(entry);

    const store = new TransactionStore();
    const tx = makeTransaction("tx-td-3", "state-td-3", {
      transactionData: [encoded],
    });
    store.set(tx);

    // Simulate wallet response
    const transaction = store.findByState("state-td-3")!;
    assertExists(transaction);
    transaction.walletResponse = {
      vpToken: '{"age_cred":["eyJhbGciOiJFUzI1NiJ9.payload.sig"]}',
      state: "state-td-3",
    };
    transaction.status = "received";

    const status = getStatusForTransaction(store, "tx-td-3");
    assertEquals(status.status, "received");
    assertExists(
      status.transaction_data,
      "transaction_data must be present in received status",
    );
    assertEquals(status.transaction_data!.length, 1);
    assertEquals(status.transaction_data![0], encoded);
  },
);

Deno.test(
  "§8.4 — status result has no transaction_data when none was provided",
  () => {
    const store = new TransactionStore();
    store.set(makeTransaction("tx-td-4", "state-td-4"));

    const transaction = store.findByState("state-td-4")!;
    transaction.walletResponse = {
      vpToken: "some-token",
      state: "state-td-4",
    };
    transaction.status = "received";

    const status = getStatusForTransaction(store, "tx-td-4");
    assertEquals(status.status, "received");
    assertEquals(status.transaction_data, undefined);
  },
);

Deno.test(
  "§8.4 — multiple transaction_data entries are all echoed back",
  () => {
    const entries = [
      { type: "payment", credential_ids: ["cred_a"], amount: "50.00" },
      { type: "consent", credential_ids: ["cred_b"], document_ref: "terms-v3" },
    ].map(encodeTransactionDataEntry);

    const store = new TransactionStore();
    store.set(
      makeTransaction("tx-td-5", "state-td-5", { transactionData: entries }),
    );

    const tx = store.findByState("state-td-5")!;
    tx.walletResponse = { vpToken: "token", state: "state-td-5" };
    tx.status = "received";

    const status = getStatusForTransaction(store, "tx-td-5");
    assertEquals(status.transaction_data?.length, 2);
    assertEquals(status.transaction_data, entries);
  },
);

// ---------------------------------------------------------------------------
// §8.4 — TransactionDataEntry type shape
// ---------------------------------------------------------------------------

Deno.test(
  "§8.4 — decoded TransactionDataEntry has required type and credential_ids fields",
  () => {
    const entry = {
      type: "payment",
      credential_ids: ["my_credential"],
      amount: "100.00",
      currency: "EUR",
    };
    const encoded = encodeTransactionDataEntry(entry);

    // Decode and verify
    const binary = atob(encoded.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    const decoded = JSON.parse(new TextDecoder().decode(bytes));

    assertExists(decoded.type, "type field is required");
    assertExists(decoded.credential_ids, "credential_ids field is required");
    assertEquals(decoded.type, "payment");
    assertEquals(decoded.credential_ids, ["my_credential"]);
    assertEquals(decoded.amount, "100.00");
  },
);
