# Issue a test credential

This guide builds a signed test credential with the `ewqwe_digital_credential` library and presents it to a running credential verifier. Use this procedure to test the verifier without a real wallet or a real issuer.

## Goal

Produce a credential of a supported type, trust its issuer in the verifier, and submit it to the `/ewqwe_api/verify` endpoint.

## Before you start

- The credential verifier runs and answers on a known URL. See [Install and run](../credential-verifier/install-and-run.md).
- The Rust toolchain with Cargo is installed.
- The `jq` tool is installed, to read values from JSON responses. Read the values by hand if `jq` is not available.
- You can write to the `issuers_cas_dir` directory of the verifier. The default directory is `issuers_cas` next to the configuration file. See [Configuration](../../reference/credential-verifier/configuration.md).
- You know the type of credential to build. See [Credential types](../../reference/digital-credential/credential-types.md).

The library signs with ES256 (ECDSA with P-256 and SHA-256). The library keeps all private keys in memory, and a test credential is valid for one hour in the SD-JWT VC format and for one year in the mDoc format.

## 1. Create the program

Create a new Cargo project, and add the library and `serde_json` as dependencies.

```toml
[package]
name = "test-credential"
version = "0.1.0"
edition = "2021"

[dependencies]
ewqwe_digital_credential = { path = "../crates/ewqwe-digital-credential" }
serde_json = "1"
```

Put the following code in `src/main.rs`. The program generates the issuing authority, stores the CA certificate, builds one credential, and writes the request body for the verify endpoint.

```rust
use ewqwe_digital_credential::CredentialIssuer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create an ephemeral authority: a CA, an issuer leaf key, and a device key.
    let issuer = CredentialIssuer::generate()?;

    // 2. Write the public CA certificate to the trusted CA directory of the verifier.
    std::fs::write("credentials_cas/test-ca.pem", &issuer.ca_cert_pem)?;

    // 3. Read the values of one OpenID4VP transaction.
    let auth_request: serde_json::Value =
        serde_json::from_slice(&std::fs::read("auth-request.json")?)?;
    let nonce = auth_request["nonce"].as_str().ok_or("missing nonce")?.to_string();
    let client_id = auth_request["client_id"].as_str().ok_or("missing client_id")?.to_string();
    let response_uri = auth_request["response_uri"].as_str().ok_or("missing response_uri")?.to_string();
    let state = auth_request["state"].as_str().ok_or("missing state")?.to_string();

    // 4. Build the credential. Select one of the three lines below.
    //    The EU Age Verification profile, vct eu.europa.ec.av.1, claim over_18.
    let credential = issuer.build_eu_age_sd_jwt(&nonce, &client_id);
    // The EUDI PID as an SD-JWT VC, vct eu.europa.ec.eudi.pid.1.
    // let credential = issuer.build_eudi_sd_jwt(&nonce, &client_id);
    // The EUDI PID as an ISO/IEC 18013-5 mDoc. This line also uses response_uri.
    // let credential = issuer.build_eudi_mdoc(&nonce, &client_id, &response_uri);

    // 5. Wrap the credential as a DCQL VP token, and write the verify request body.
    let vp_token = serde_json::json!({ "eu_age_credential": [credential] }).to_string();
    let body = serde_json::json!({
        "vp_token": vp_token,
        "state": state,
        "client_id": client_id,
    });
    std::fs::write("verify-request.json", serde_json::to_vec_pretty(&body)?)?;

    println!("wrote verify-request.json");
    Ok(())
}
```

## 2. Generate the issuing authority

The `CredentialIssuer::generate` call creates three P-256 key pairs and the matching X.509 certificates. The call returns the issuer object with the following fields.

| Field               | Content                                     |
| :------------------ | :------------------------------------------ |
| `ca_cert_pem`       | The self-signed CA certificate, in PEM form |
| `issuer_cert_der`   | The issuer leaf certificate, in DER form    |
| `device_pubkey_jwk` | The device public key, as a JWK             |

The library writes the issuer leaf certificate and the CA certificate into each credential automatically. The verifier reads the two certificates from the credential.

## 3. Trust the issuer certificate

The verifier trusts an issuer only when the issuer certificate chains to a CA in the trusted CA directory.

1. Write the value of `issuer.ca_cert_pem` to a `.pem` file in the `issuers_cas_dir` directory. The program above writes `issuers_cas/test-ca.pem`.
2. If the verifier runs in another directory, move the file to the configured `issuers_cas_dir` instead.
3. Restart the credential verifier. The verifier loads the directory at startup only, so a new file needs a restart.

Expected result: the log line `Loaded credential issuer CAs at startup` reports a count of at least one.

> [!NOTE]
> A test credential is rejected when its issuer CA is missing from the directory. The verify response then reports `"issuer_trusted": false`.

## 4. Start a transaction and read its parameters

The credential must bind to the nonce and the `client_id` of one transaction, and an mDoc must also bind to the `response_uri`. Start a transaction, and save the response in a file.

```bash
# Start a transaction. Save the response.
curl --cacert ca.pem --cert client.pem --key client.key \
  -H 'Content-Type: application/json' \
  -d '{"profile":"annex-a","credential_type":"proof-of-age"}' \
  https://localhost:9443/ewqwe_api/openid4vp/init > init-response.json

# Read the transaction id. The examples use jq to read JSON.
TRANSACTION_ID=$(jq -r .transaction_id init-response.json)

# Fetch the authorization request. Save it where the program reads it.
curl --cacert ca.pem --cert client.pem --key client.key \
  -H 'Accept: application/json' \
  "https://localhost:9443/ewqwe_api/openid4vp/request/$TRANSACTION_ID" > auth-request.json
```

Expected result: `init-response.json` holds the `transaction_id` value, and `auth-request.json` holds the values `state`, `nonce`, `client_id`, and `response_uri`. The program reads those four values from `auth-request.json` in the next step.

For the Annex A profile, the verifier derives `client_id` as `redirect_uri:` followed by the `response_uri`. The `response_uri` is the `public_root_url` followed by `/ewqwe_api/openid4vp/direct_post`.

The `credential_type` value shapes the authorization request for a real wallet. This guide bypasses the wallet, so the value does not restrict the credential that you build in the next step.

> [!IMPORTANT]
> Use the values from one transaction only. The verifier rejects a presentation whose nonce or session data belongs to a different transaction.

The verifier requires mutual TLS by default. Replace `ca.pem`, `client.pem`, and `client.key` with the certificate files of your setup. For the details, see [Configure TLS](../credential-verifier/configure-tls.md) and [TLS authentication](../../reference/credential-verifier/tls-authentication.md).

## 5. Build and run the program

Run the program. It builds the credential and writes the file `verify-request.json`.

Run the program and the `curl` commands from the same directory, so that the files `auth-request.json` and `verify-request.json` resolve.

```bash
cargo run
```

Expected result: the line `wrote verify-request.json`.

| Builder               | Type                | Format    | Claims                                                   |
| :-------------------- | :------------------ | :-------- | :------------------------------------------------------- |
| `build_eu_age_sd_jwt` | EU Age Verification | SD-JWT VC | `over_18`                                                |
| `build_eudi_sd_jwt`   | EUDI PID            | SD-JWT VC | `given_name`, `family_name`, `birth_date`, `age_over_18` |
| `build_eudi_mdoc`     | EUDI PID            | mso_mdoc  | `given_name`, `family_name`, `birth_date`, `age_over_18` |

The credential appears in the `vp_token` field of `verify-request.json`. An SD-JWT VC presentation starts with a JWT and ends with the KB-JWT, and the two parts are separated by `~`. An mDoc presentation is a Base64URL-encoded CBOR value.

## 6. Submit the credential to the verifier

Send the request body to the verify endpoint.

```bash
curl --cacert ca.pem --cert client.pem --key client.key \
  -H 'Content-Type: application/json' \
  --data @verify-request.json \
  https://localhost:9443/ewqwe_api/verify
```

Expected result, in the success case:

```json
{
  "success": true,
  "message": "Credential verified successfully",
  "verification_details": {
    "signature_valid": true,
    "not_expired": true,
    "issuer_trusted": true
  },
  "attestation": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

The `attestation` value is a signed JWT. The claims of the credential appear in the attestation payload when the verification succeeds.

## Troubleshooting

| Symptom                                                          | Cause                                                        | Fix                                                               |
| :--------------------------------------------------------------- | :----------------------------------------------------------- | :---------------------------------------------------------------- |
| `"issuer_trusted": false`                                        | The issuer CA is not in the trusted directory, or no restart | Write the CA PEM, then restart the verifier.                      |
| `Nonce mismatch: presentation nonce does not match server nonce` | The credential uses the nonce of a different transaction     | Rebuild the credential with the nonce of the current transaction. |
| `state is required for mDoc verification`                        | An mDoc presentation arrived without a `state` value         | Add the `state` field of the transaction to the request body.     |
| `issuer JWT is missing the required x5c header`                  | The SD-JWT VC value did not come from this library           | Build the credential with a `build_*` function of the library.    |
| `deviceAuth.deviceMac is not supported by this verifier`         | The mDoc used a `COSE_Mac0` value for the holder proof       | Use a wallet that produces a `deviceSignature`.                   |
| `Credential has expired`                                         | The SD-JWT VC validity time of one hour passed               | Run the program again to build a fresh credential.                |

## Related topics

- [Credential formats](../../reference/digital-credential/credential-formats.md) describes the structure of both formats.
- [Selective disclosure](../../explanation/digital-credential/selective-disclosure.md) explains why a test credential reveals all of its claims.
- [Verify a credential](../credential-verifier/verify-a-credential.md) describes the verify endpoint in detail.
- [HTTP API](../../reference/credential-verifier/http-api.md) lists the endpoint fields and the response schema.
