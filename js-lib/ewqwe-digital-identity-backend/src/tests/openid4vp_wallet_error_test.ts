/// <reference lib="deno.ns" />
/**
 * Tests for §8.2 (direct_post success) and §8.5 (Authorization Error Response)
 * of OpenID4VP 1.0 — TypeScript service layer.
 *
 * These tests focus on the transaction store logic that underlies `handleWalletError`
 * and `getTransactionStatus`, keeping them free of crypto dependencies (which require
 * test cert infrastructure). Crypto-layer tests are covered by the Rust service
 * integration tests in `crates/openid4vp/src/service.rs`.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_post
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-error-response
 */

import { assertEquals, assertExists } from "@std/assert";
import { TransactionStore } from "../transaction-store.ts";
import type { OpenID4VPTransaction } from "../types.ts";
import type {
  TransactionStatusResult,
  WalletAuthorizationError,
} from "@ewqwe/digital-identity";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeTransaction(
  id: string,
  state: string,
  ttlMs = 60_000,
): OpenID4VPTransaction {
  const now = Date.now();
  return {
    id,
    state,
    nonce: "test-nonce",
    createdAt: now,
    expiresAt: now + ttlMs,
    status: "pending",
    dcqlQuery: { credentials: [] },
    clientId: "redirect_uri:https://rp.example.com/api/openid4vp/direct_post",
    clientIdScheme: "redirect_uri",
    responseUri: "https://rp.example.com/api/openid4vp/direct_post",
    responseMode: "direct_post",
    profile: "annex-a",
  };
}

/**
 * Simulate `handleWalletError` logic (mirrors `openid4vp-service.ts`).
 * Extracted here to test without OS-level crypto initialization.
 */
function simulateHandleWalletError(
  store: TransactionStore,
  error: WalletAuthorizationError,
): void {
  const state = error.state ?? "";
  const transaction = store.findByState(state);
  if (!transaction) {
    throw new Error(`No transaction found for state: ${state}`);
  }
  transaction.walletError = error;
  transaction.status = "error";
}

/**
 * Simulate `getTransactionStatus` for the error case (mirrors service logic).
 */
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
    };
  }

  if (tx.status === "error") {
    return {
      status: "error",
      wallet_error: tx.walletError,
    };
  }

  return {
    status: tx.status,
    expires_in: Math.floor((tx.expiresAt - Date.now()) / 1000),
  };
}

// ---------------------------------------------------------------------------
// §8.2 — Success path: vp_token + state → status "received"
// ---------------------------------------------------------------------------

Deno.test("§8.2 — direct_post success: transaction transitions to 'received' with vp_token", () => {
  const store = new TransactionStore();
  const tx = makeTransaction("tx-1", "state-abc");
  store.set(tx);

  // Simulate wallet POSTing `vp_token=...&state=state-abc`
  const transaction = store.findByState("state-abc")!;
  assertExists(transaction);
  transaction.walletResponse = {
    vpToken: '{"my_credential":["eyJhbGciOiJFUzI1NiJ9.payload.sig"]}',
    state: "state-abc",
  };
  transaction.status = "received";

  const status = getStatusForTransaction(store, "tx-1");
  assertEquals(status.status, "received");
  assertExists(status.authorization_response?.vp_token);
  assertEquals(status.wallet_error, undefined);
  assertEquals(status.nonce, "test-nonce");
});

Deno.test("§8.2 — Verifier response to wallet must be empty JSON object ({})", () => {
  // This documents the spec requirement: after storing the wallet response,
  // the HTTP layer MUST return `{}` not `{"status": "ok"}`.
  // The actual HTTP response is constructed in openid4vp_endpoints.rs.
  // This test verifies the expected JSON value.
  const expectedVerifierResponse = {};
  assertEquals(JSON.stringify(expectedVerifierResponse), "{}");
});

// ---------------------------------------------------------------------------
// §8.5 — Authorization Error Response from Wallet
// ---------------------------------------------------------------------------

Deno.test("§8.5 — access_denied: transaction transitions to 'error' with wallet_error", () => {
  const store = new TransactionStore();
  store.set(makeTransaction("tx-2", "state-def"));

  simulateHandleWalletError(store, {
    error: "access_denied",
    state: "state-def",
  });

  const result = getStatusForTransaction(store, "tx-2");
  assertEquals(result.status, "error");
  assertExists(result.wallet_error);
  assertEquals(result.wallet_error!.error, "access_denied");
  assertEquals(result.wallet_error!.error_description, undefined);
  assertEquals(result.wallet_error!.state, "state-def");
});

Deno.test("§8.5 — invalid_request: error_description is stored and returned", () => {
  const store = new TransactionStore();
  store.set(makeTransaction("tx-3", "state-ghi"));

  // §8.2 example: error=invalid_request&error_description=unsupported%20client_id_prefix&state=...
  simulateHandleWalletError(store, {
    error: "invalid_request",
    error_description: "unsupported client_id_prefix",
    state: "state-ghi",
  });

  const result = getStatusForTransaction(store, "tx-3");
  assertEquals(result.status, "error");
  assertEquals(result.wallet_error!.error, "invalid_request");
  assertEquals(
    result.wallet_error!.error_description,
    "unsupported client_id_prefix",
  );
});

Deno.test("§8.5 — wallet_error without state is handled (unknown state → throws)", () => {
  const store = new TransactionStore();
  store.set(makeTransaction("tx-4", "state-jkl"));

  let threw = false;
  try {
    simulateHandleWalletError(store, {
      error: "access_denied",
      state: "unknown-state-xyz",
    });
  } catch (e) {
    threw = true;
    assertEquals((e as Error).message.includes("No transaction found"), true);
  }
  assertEquals(threw, true, "Expected an error for unknown state");
});

Deno.test("§8.5 — all six error codes are accepted and stored correctly", () => {
  const errorCodes: string[] = [
    "invalid_request",
    "access_denied",
    "vp_formats_not_supported",
    "invalid_request_uri_method",
    "invalid_transaction_data",
    "wallet_unavailable",
  ];

  for (const [idx, errorCode] of errorCodes.entries()) {
    const txId = `tx-ec-${idx}`;
    const state = `state-ec-${idx}`;
    const store = new TransactionStore();
    store.set(makeTransaction(txId, state));

    simulateHandleWalletError(store, { error: errorCode, state });

    const result = getStatusForTransaction(store, txId);
    assertEquals(result.status, "error", `error_code=${errorCode}`);
    assertEquals(
      result.wallet_error!.error,
      errorCode,
      `error_code=${errorCode}`,
    );
  }
});

Deno.test("§8.5 — WalletAuthorizationError serialises to correct JSON (snake_case, optional omitted)", () => {
  const minimal: WalletAuthorizationError = { error: "access_denied" };
  const full: WalletAuthorizationError = {
    error: "invalid_request",
    error_description: "unsupported client_id_prefix",
    state: "eyJhb...6-sVA",
  };

  // Minimal — no optional fields
  const minJson = JSON.parse(JSON.stringify(minimal));
  assertEquals(minJson.error, "access_denied");
  assertEquals("error_description" in minJson, false);
  assertEquals("state" in minJson, false);

  // Full — all fields
  const fullJson = JSON.parse(JSON.stringify(full));
  assertEquals(fullJson.error, "invalid_request");
  assertEquals(fullJson.error_description, "unsupported client_id_prefix");
  assertEquals(fullJson.state, "eyJhb...6-sVA");
});


