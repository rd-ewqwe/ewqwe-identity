# Present a stored credential

This tutorial presents a credential from the demo wallet extension to the demo webapp, and reads the verification result.

## What you need

- The running demo environment from [Run the demo webapp](../webapp/run-the-demo-webapp.md).
- The demo wallet extension from [Install the demo wallet extension](./install-the-demo-wallet-extension.md).

## Steps

### 1. Open the demo webapp

Open `https://localhost:5174/`.

### 2. Keep the default credential type

The **Proof of Age** credential type is active. Keep it.

### 3. Keep the default protocol

The **Protocol** dropdown shows **W3C Digital Credentials with fallback to OpenID4VP**. Keep it. In this protocol, the webapp sends the request to the demo wallet extension.

### 4. Request the credential

Click **Request Credentials**.

Expected: the demo wallet extension shows a credential selection overlay over the page. The overlay header reads **EU AV Wallet**, and the subtitle reads **Select a credential to share**. The overlay lists the credentials that match the request.

The webapp built an OpenID4VP request with a DCQL query. A DCQL query is a structured filter that names the claims that the relying party needs. The content script of the demo wallet received the request and matched it against the stored credentials.

### 5. Choose a credential

Click a credential card, for example a Proof of Age credential.

Expected: the overlay closes and the webapp receives the credential as a verifiable presentation.

### 6. Read the result

Expected: the page moves to the **Verification Result** section. A successful result reads **Verification Successful** and lists the verified claims.

The webapp sent the verifiable presentation to the credential verifier. The credential verifier checked the presentation and returned the result through the webapp API server. See [Selective disclosure](../../explanation/digital-credential/selective-disclosure.md).

## Troubleshooting

| Symptom                      | Cause                                                     | Action                                                                                                  |
| :--------------------------- | :-------------------------------------------------------- | :------------------------------------------------------------------------------------------------------ |
| The overlay does not appear  | The browser did not deliver the request to the extension. | Use the cross-device flow in [Complete an age verification](../webapp/complete-an-age-verification.md). |
| The wallet shows no match    | The wallet holds no credential of the requested type.     | Open the wallet, click **Reset**, and request again.                                                    |
| The result reports a failure | The demo credential carries test data.                    | The demo wallet is not a certified wallet. Read the error details.                                      |

## Next steps

- [Complete an age verification](../webapp/complete-an-age-verification.md)
- [Credential types](../../reference/digital-credential/credential-types.md)
