# Complete an age verification

This tutorial continues from [Run the verifier app](./run-the-verifier-app.md). With the verifier app running and an operator signed in, you generate a QR code, scan it with a wallet, and read the verified result.

## What you need

- The verifier app running, with an operator signed in. See [Run the verifier app](./run-the-verifier-app.md).
- A wallet that holds a Proof of Age credential. To set up a wallet, see [Test with the age verification app](../../how-to-guides/credential-verifier/test-with-the-av-app.md) or [Test with the EUDI wallet](../../how-to-guides/credential-verifier/test-with-the-eudi-wallet.md).

## Steps

### 1. Select the credential type

On the control page, open the credential type selector and choose the type that your wallet holds. The default type is **Proof of Age**.

When the server allows only one credential type, the app hides the selector and starts the transaction automatically.

### 2. Generate the QR code

Click **Generate QR Code**.

Expected: the page shows a QR code and a status badge with the value `pending`. The app polls the transaction every 2 seconds.

### 3. Scan the QR code

Open the wallet on the holder device, choose the option to present a credential, and scan the QR code. Approve the request.

Expected: the status badge changes from `pending` to `scanned`, and then to `verified`.

### 4. Read the result

When the badge shows `verified`, the holder presentation passed verification. The page shows the verified claims, which for a Proof of Age credential is the boolean claim `age_over_18`. Click **New Verification** to start another transaction.

## The status values

| Status     | Meaning                                  |
| :--------- | :--------------------------------------- |
| `pending`  | The wallet has not scanned the code.     |
| `scanned`  | The wallet received the request.         |
| `verified` | The credential passed verification.      |
| `failed`   | The credential failed verification.     |
| `expired`  | The transaction passed its time to live. |

A `failed` result shows the errors that the verifier returned. The most common cause is an untrusted issuer. See [the security model](../../explanation/credential-verifier/security-model.md).

## What happened

In step 2 the verifier app asked the credential verifier to start a transaction. The credential verifier created a random nonce, stored the transaction, and returned an OpenID4VP authorization request. The QR code carries that request.

In step 3 the wallet read the request, built a verifiable presentation from the stored credential, and sent the presentation to the credential verifier. The credential verifier read the nonce from its own transaction store, compared it with the nonce in the presentation, verified the issuer signature and the holder signature, and signed an attestation.

In step 4 the verifier app read the transaction status and showed the result. The verifier recorded the verification in its journal, when the journal is enabled.

## Troubleshooting

| Symptom                              | Cause                                        | Action                                                       |
| :----------------------------------- | :------------------------------------------- | :----------------------------------------------------------- |
| The badge stays `pending`            | The wallet did not scan the code.            | Scan the code again, or generate a new code.                 |
| The QR code expires before the scan  | The transaction passed its time to live.     | Generate a new QR code.                                      |
| The result is `failed`               | The credential failed a check.               | Read the errors. An untrusted issuer is the common cause.    |
| QR generation returns `400`          | The credential type is not allowed.          | Check `allowed_credential_types` and the per-user types.     |
| The wallet rejects the request       | The wallet does not trust the verifier.      | Load the verifier CA certificate into the wallet trust store. |

## Next steps

- [Configure the verifier app](../../how-to-guides/verifier-app/configure-the-verifier-app.md)
- [Verification process](../../explanation/credential-verifier/verification-process.md)
- [Develop your own relying-party UI](../../how-to-guides/credential-verifier/develop-a-relying-party-ui.md)
