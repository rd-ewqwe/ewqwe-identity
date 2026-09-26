# Configure TLS

This guide configures the TLS listener of the credential verifier and, optionally, mutual TLS. Mutual TLS means the server also requires a client certificate, so the server can identify the calling relying party.

TLS encrypts every connection. Mutual TLS adds authentication of the caller, and the verifier uses that authentication to scope the verification journal to one owner.

## Prerequisites

- A running server. See [install and run the server](install-and-run.md).
- A server private key in PKCS#8 PEM format, a server certificate in X.509 PEM format, and a CA chain as concatenated PEM certificates.
- For mutual TLS, a CA chain that signs the client certificates of your relying parties.

## Configure server TLS

1. Prepare the three PEM files and note their paths. Each path is resolved against the directory that contains `credential-server.toml`.

2. Add or edit the `[tls_params]` section.

   ```toml
   [tls_params]
   server_private_key = "../certificates/tls/ewqwe.server.key.pem"
   server_certificate = "../certificates/tls/ewqwe.server.cert.pem"
   server_ca_chain = "../certificates/tls/ewqwe.ca.pem"
   ```

   The table below describes each field.

| Field                  | Required | Content                                                      |
| :--------------------- | :------- | :----------------------------------------------------------- |
| `server_private_key`   | Yes      | The server private key, in PKCS#8 PEM format.                |
| `server_certificate`   | Yes      | The server certificate, in X.509 PEM format.                 |
| `server_ca_chain`      | Yes      | The CA chain, as one or more PEM certificates.               |
| `client_ca_cert_chain` | No       | The CA chain that signs client certificates, for mutual TLS. |

3. Restart the server and check the startup output.

   ```text
   INFO credential_verifier: Server will listen on https://127.0.0.1:9443
   INFO credential_verifier::server::start: Attestation Provider server listening on 127.0.0.1:9443
   ```

4. Test the server certificate. The `/version` endpoint requires no client certificate.

   ```bash
   curl -sk https://localhost:9443/version
   ```

   Expected output:

   ```json
   { "version": "0.1.0" }
   ```

   If `curl` reports a certificate error rather than a JSON response, the host name in the request does not match a DNS subject alternative name of the server certificate. The test certificate provides `demo.ewqwe.local`, `localhost`, and `127.0.0.1`.

## Configure mutual TLS

1. Add the `client_ca_cert_chain` field to `[tls_params]`.

   ```toml
   [tls_params]
   server_private_key = "../certificates/tls/ewqwe.server.key.pem"
   server_certificate = "../certificates/tls/ewqwe.server.cert.pem"
   server_ca_chain = "../certificates/tls/ewqwe.ca.pem"
   client_ca_cert_chain = "../certificates/tls/ewqwe.ca.pem"
   ```

   When you omit `client_ca_cert_chain`, the server verifies client certificates against `server_ca_chain` instead.

2. Restart the server. The server logs one line for each loaded client CA.

   ```text
   INFO credential_verifier::tls::openssl_config: Client CA cert subject: "CN=acme.com"
   ```

3. Call an endpoint that requires authentication, and present a client certificate.

   ```bash
   curl -sk \
     --cert certificates/tls/ewqwe.user1.cert.pem \
     --key certificates/tls/ewqwe.user1.key.pem \
     https://localhost:9443/ewqwe_api/journal/user1.acme.com/entries
   ```

   Expected output, when the client owns no journal entries yet:

   ```json
   []
   ```

4. Inspect the handshake when a call fails.

   ```bash
   openssl s_client -connect localhost:9443 \
     -cert certificates/tls/ewqwe.user1.cert.pem \
     -key certificates/tls/ewqwe.user1.key.pem \
     -CAfile certificates/tls/ewqwe.ca.pem -brief
   ```

## How the verifier uses the client certificate

The verifier reads the Common Name (CN) of the client certificate and uses it as the authenticated username. The journal then uses that username to scope each entry and to check ownership.

- Every endpoint under `/ewqwe_api` that a relying party calls requires a client certificate: `/verify`, `/.well-known/issuer_certs`, `/openid4vp/init`, `/openid4vp/status/{id}`, and the three journal endpoints.
- The wallet-facing endpoints `/openid4vp/direct_post`, `/openid4vp/request/{id}`, and `/openid4vp/.well-known/jwks.json` require no client certificate, because a wallet has no certificate from the verifier client CA.
- The `/version` endpoint requires no client certificate.

A request without a client certificate to a protected endpoint returns `401 Unauthorized`. A client certificate whose CN ends with `*` is rejected, because a wildcard could match many callers.

> [!WARNING]
> The `disable_authentication` setting removes the client-certificate requirement. Use it only for local development and tests.

## Limit the cipher suites

Set `tls_cipher_suites` to a colon-separated list to restrict the accepted cipher suites. When you set this field, the server enables only the listed suites and selects the TLS versions that they require. When you omit the field, the server uses the Mozilla intermediate profile with TLS 1.2 as the minimum version.

```toml
[tls_params]
server_private_key = "../certificates/tls/ewqwe.server.key.pem"
server_certificate = "../certificates/tls/ewqwe.server.cert.pem"
server_ca_chain = "../certificates/tls/ewqwe.ca.pem"
tls_cipher_suites = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
```

The names `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`, and `TLS_AES_128_CCM_8_SHA256` are TLS 1.3 suites. Any other name is treated as a TLS 1.2 suite.

## Troubleshooting

- **`curl` reports a certificate verify error on `/version`.** The host name does not match a DNS subject alternative name of the server certificate. Use a name from the certificate, or add `-k` for a local test.
- **The protected call returns `401 Unauthorized` with the body `Authentication required`.** The request carried no client certificate and `disable_authentication` is false. Pass `--cert` and `--key`, or create a client certificate from the CA.
- **The TLS handshake fails when a client certificate is presented.** The client certificate is not signed by a CA in `client_ca_cert_chain`. Check the issuer of the client certificate.
- **The protected call returns `401 Unauthorized` with a wildcard message.** The client certificate has a CN that ends with `*`. Use a CN without a wildcard.
- **The server stops with a PEM parse error.** Confirm that the key is PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`), that the certificate is X.509 PEM, and that the CA chain holds only PEM certificates.
- **The journal call returns `401 Unauthorized` with an access-denied message.** The CN of the client certificate does not equal the `{username}` in the path. The path must name the authenticated user.

## Next steps

- Choose the transaction store and the journal backend in [configure storage](configure-storage.md).
- Read the endpoint list in [the HTTP API reference](../../reference/credential-verifier/http-api.md).
