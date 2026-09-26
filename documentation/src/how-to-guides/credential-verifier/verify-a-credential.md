# Verify a credential

This guide sends a verification request to the credential verifier and reads the signed attestation that comes back. You create a transaction, let a wallet present a credential, and then ask the verifier to check the presentation.

The example uses the Annex A profile and a proof-of-age credential.

## Prerequisites

- A running verifier with mutual TLS enabled. See [install and run the server](install-and-run.md) and [configure TLS](configure-tls.md).
- A client certificate that the verifier trusts. The examples use `certificates/tls/ewqwe.user1.cert.pem`.
- A wallet that can present a credential to the verifier, such as the EUDI Wallet or the AV app. See [test with the EUDI wallet](test-with-the-eudi-wallet.md) or [test with the AV app](test-with-the-av-app.md).
- `jq` for the JSON extraction steps.

Run the commands from the repository root, so that the relative certificate paths resolve.

## Understand the request pattern

The verifier separates the wallet interaction from the check. You set up a transaction first, the wallet answers that transaction, and you then send the presentation for verification. Three endpoints carry the pattern:

| Step                    | Endpoint                               | Who calls it  | What it does                               |
| :---------------------- | :------------------------------------- | :------------ | :----------------------------------------- |
| Create a transaction    | `POST /ewqwe_api/openid4vp/init`       | Relying party | Stores the nonce and the request.          |
| Read the transaction    | `GET /ewqwe_api/openid4vp/status/{id}` | Relying party | Returns the presentation from the wallet.  |
| Verify the presentation | `POST /ewqwe_api/verify`               | Relying party | Runs the checks and signs the attestation. |

Set up shared values for the commands below.

```bash
CERT=certificates/tls/ewqwe.user1.cert.pem
KEY=certificates/tls/ewqwe.user1.key.pem
BASE=https://localhost:9443
```

## Steps

1. Create the transaction. The `public_url` is the address that the wallet uses for the callback, so it must be reachable by the wallet and must match a DNS subject alternative name of the server certificate. The `state` value is yours to choose; the verifier binds it to the transaction and expects it again at verification.

   ```bash
   curl -sk --cert "$CERT" --key "$KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "public_url": "https://localhost:9443",
       "profile": "annex-a",
       "credential_type": "proof-of-age",
       "state": "demo-state-0001"
     }' \
     "$BASE/ewqwe_api/openid4vp/init" | tee init.json
   ```

   Expected output:

   ```json
   {
     "transaction_id": "6f1c8a2e-...",
     "client_id": "redirect_uri:https://localhost:9443/ewqwe_api/openid4vp/direct_post",
     "client_id_scheme": "redirect_uri",
     "request_uri": "https://localhost:9443/ewqwe_api/openid4vp/request/6f1c8a2e-...",
     "authorization_request_uri": "av://?client_id=...&response_type=vp_token&...",
     "expires_in": 300,
     "profile": "annex-a"
   }
   ```

2. Extract the transaction values for later steps.

   ```bash
   TRANSACTION_ID="$(jq -r .transaction_id init.json)"
   CLIENT_ID="$(jq -r .client_id init.json)"
   ```

3. Present the credential with a wallet. Give the wallet the `authorization_request_uri` from the previous response, as a QR code or as a deep link. The wallet sends the presentation to the verifier `response_uri`, and the verifier stores it in the transaction. Follow [test with the EUDI wallet](test-with-the-eudi-wallet.md) or [test with the AV app](test-with-the-av-app.md) for this step.

4. Read the transaction status. Repeat this call until `status` is `received`.

   ```bash
   curl -sk --cert "$CERT" --key "$KEY" \
     "$BASE/ewqwe_api/openid4vp/status/$TRANSACTION_ID" | tee status.json
   ```

   Expected output when the wallet has answered:

   ```json
   {
     "status": "received",
     "authorization_response": {
       "vp_token": "{\"proof_of_age\":[\"b3JnLmlzby4x...\"]}",
       "presentation_submission": null,
       "state": "demo-state-0001"
     },
     "nonce": "X9d2..."
   }
   ```

   The `status` value is `pending` until the wallet answers, and then `received`. A wallet that sends an error response instead of a presentation sets the status to `error`.

5. Extract the presentation and the state.

   ```bash
   STATE="$(jq -r .authorization_response.state status.json)"
   VP_TOKEN="$(jq -r .authorization_response.vp_token status.json)"
   ```

6. Send the presentation for verification. The `state` must match the transaction, and the `client_id` must match the value from the init response.

   ```bash
   jq -n --arg vp "$VP_TOKEN" --arg st "$STATE" --arg cid "$CLIENT_ID" \
     '{vp_token: $vp, presentation_submission: null, state: $st, client_id: $cid}' \
     > verify_request.json

   curl -sk --cert "$CERT" --key "$KEY" \
     -H "Content-Type: application/json" \
     --data @verify_request.json \
     "$BASE/ewqwe_api/verify" | tee verify_response.json
   ```

   Expected output when the checks pass:

   ```json
   {
     "success": true,
     "message": "Credential verified successfully",
     "verification_details": {
       "signature_valid": true,
       "not_expired": true,
       "issuer_trusted": true
     },
     "attestation": "eyJhbGciOiJFUzI1NiIsImtpZCI6..."
   }
   ```

   Expected output when a check fails. An mDoc presentation returns HTTP `400` with the reason as a JSON string, because the verifier cannot return a partial result for an mDoc.

   ```json
   "bad request: mDoc issuerAuth certificate chain is not trusted: the issuer CA is not in the trusted certificates directory"
   ```

   An SD-JWT VC behaves differently. The endpoint returns HTTP `200` with `success` false, and the attestation records the failure without the claims.

   ```json
   {
     "success": false,
     "message": "Credential verification failed",
     "verification_details": {
       "signature_valid": false,
       "not_expired": true,
       "issuer_trusted": false
     },
     "attestation": "eyJhbGciOiJFUzI1NiIsImtpZCI6...",
     "errors": ["Issuer certificate does not chain to a trusted CA"]
   }
   ```

7. Read the attestation. Decode the payload of the JWT to inspect the verified claims.

   ```bash
   ATTESTATION="$(jq -r .attestation verify_response.json)"

   python3 -c "import base64, json, sys; p = sys.argv[1].split('.')[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4))), indent=2))" "$ATTESTATION"
   ```

   Expected payload for a successful proof-of-age verification. The exact values depend on the credential and the transaction.

   ```json
   {
     "iss": "ewqwe.acme.com",
     "sub": "6f1c8a2e-...",
     "aud": "redirect_uri:https://localhost:9443/ewqwe_api/openid4vp/direct_post",
     "iat": 1770000000,
     "nbf": 1769999995,
     "exp": 1770000300,
     "jti": "550e8400-e29b-41d4-a716-446655440000",
     "verified": true,
     "nonce": "X9d2...",
     "doc_type": "eu.europa.ec.av.1",
     "namespace": "eu.europa.ec.av.1",
     "age_over_18": true
   }
   ```

   The `iss` claim is the common name of the attestation signing certificate. The `jti` claim is unique to this attestation, so you can use it as an idempotency key.

8. Verify the attestation signature. The JWKS endpoint is public and returns the attestation key together with the `kid` that appears in the JWT header.

   ```bash
   curl -sk "$BASE/ewqwe_api/openid4vp/.well-known/jwks.json"
   ```

   Select the key whose `kid` equals the `kid` of the attestation, and verify the JWT signature with that key. For the claim list, see [attestations](../../reference/credential-verifier/attestations.md).

9. Confirm that the transaction is consumed. Send the same request body again.

   ```bash
   curl -sk --cert "$CERT" --key "$KEY" \
     -H "Content-Type: application/json" \
     --data @verify_request.json \
     "$BASE/ewqwe_api/verify"
   ```

   An mDoc presentation now returns `400` with `state is required for mDoc verification`, because the verifier consumed the stored transaction and no longer has the request context to rebuild the session transcript.

## Troubleshooting

- **The response is `401 Unauthorized`.** The request carried no client certificate. Add `--cert` and `--key`.
- **The response is `404` with `{"error": "..."}`.** The transaction id is unknown, or you created the transaction against another server instance.
- **The response is `410 Gone`.** The transaction exceeded `transaction_ttl_secs` and expired. Create a new transaction.
- **The response is `400` with `client_id does not match the transaction-bound request`.** Send the `client_id` value from the init response.
- **The response is `400` with `state is required for mDoc verification`.** An mDoc presentation needs the transaction, so include `state`.
- **The response is `400` with an untrusted-issuer message.** The issuer CA of the credential is not in `credentials_cas_dir`. Add the CA file and restart the server, because the directory is read only at startup.
- **The response is `400` with a decode message.** The `vp_token` is not a valid SD-JWT VC, mDoc `DeviceResponse`, or direct JSON presentation. Check that you copied the value without truncation.
- **`success` is `false` with a nonce mismatch error.** The presentation does not belong to the transaction that `state` names. Use the `vp_token` and the `state` from the same status response.
- **The status stays `pending`.** The wallet did not reach the `response_uri`. Check that the wallet can reach `public_url` and that the wallet trusts the server certificate.
- **The response is `500` and the log shows a journal error.** The checks passed but the journal write failed. See [configure storage](configure-storage.md).

## Next steps

- Read the endpoint reference in [the HTTP API reference](../../reference/credential-verifier/http-api.md).
- Read the check sequence in [the verification process](../../explanation/credential-verifier/verification-process.md).
