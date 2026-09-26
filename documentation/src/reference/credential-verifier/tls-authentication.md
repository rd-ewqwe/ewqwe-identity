# TLS and mutual TLS

The credential verifier serves every endpoint over TLS. A relying-party endpoint additionally requires a client certificate. This page documents the TLS parameters, the certificate formats, the client identifier, and the authentication flow.

## TLS parameters

The `[tls_params]` table configures the TLS listener.

| Key                    | Type   | Required | Default                 | Description                                          |
| :--------------------- | :----- | :------- | :---------------------- | :--------------------------------------------------- |
| `server_private_key`   | string | Yes      | —                       | Server private key in PKCS#8 PEM format.             |
| `server_certificate`   | string | Yes      | —                       | Server X.509 certificate in PEM format.              |
| `server_ca_chain`      | string | Yes      | —                       | CA chain in PEM format.                              |
| `client_ca_cert_chain` | string | No       | `server_ca_chain`       | CA chain that validates client certificates.         |
| `tls_cipher_suites`    | string | No       | Mozilla intermediate v5 | Colon-separated list of TLS cipher suites to enable. |

```toml
[tls_params]
server_private_key   = "certs/server.key.pem"
server_certificate   = "certs/server.cert.pem"
server_ca_chain      = "certs/ca.chain.pem"
client_ca_cert_chain = "certs/client-ca.pem"
```

All paths are relative to the configuration file directory. See [Configuration](./configuration.md) for the path resolution rule.

### Protocol versions and cipher suites

When `tls_cipher_suites` is omitted, the server builds the listener from the Mozilla intermediate v5 profile and allows TLS 1.2 through TLS 1.3.

When `tls_cipher_suites` is set, the server builds the listener from the Mozilla modern v5 profile and applies the given list. The server splits the list into TLS 1.3 suites and TLS 1.2 suites.

| List content        | Minimum protocol version |
| :------------------ | :----------------------- |
| TLS 1.3 suites only | TLS 1.3                  |
| TLS 1.2 suites only | TLS 1.2                  |
| Both groups         | TLS 1.2                  |

The TLS 1.3 suites that the server recognizes are `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`, and `TLS_AES_128_CCM_8_SHA256`.

## Certificate formats

| Material    | Encoding               | Expected header                                                     |
| :---------- | :--------------------- | :------------------------------------------------------------------ |
| Private key | PKCS#8 PEM             | `-----BEGIN PRIVATE KEY-----`                                       |
| Certificate | X.509 PEM              | `-----BEGIN CERTIFICATE-----`                                       |
| CA chain    | Concatenated X.509 PEM | One `-----BEGIN CERTIFICATE-----` block per certificate, root last. |

The server loads the server private key with `PKey::private_key_from_pem`, the server certificate with `X509::from_pem`, and each CA chain with `X509::stack_from_pem`. A file that fails to parse stops the server at startup with a configuration error.

## Mutual TLS

The server always configures client certificate verification. The server builds an X.509 trust store from the `client_ca_cert_chain` file. When `client_ca_cert_chain` is absent, the server uses `server_ca_chain`.

The server sets the OpenSSL verify mode to `PEER`. In this mode the server requests a client certificate during the TLS handshake and verifies the certificate when the client presents one. The handshake still completes when the client presents no certificate. The credential verifier then enforces authentication at the application layer, so an unauthenticated request to a relying-party endpoint receives status `401`.

## Relying-party authentication

The server authenticates a relying party with the Common Name (CN) of the client certificate. The table below describes the authentication stages.

| Order | Stage            | Action                                                                 |
| :---- | :--------------- | :--------------------------------------------------------------------- |
| 1     | TLS handshake    | Verify the client certificate chain against the client CA trust store. |
| 2     | Connection setup | Store the peer certificate on the connection.                          |
| 3     | `SslAuth`        | Read the CN of the peer certificate and treat the CN as the username.  |
| 4     | `EnsureAuth`     | Require an authenticated username on a relying-party endpoint.         |
| 5     | Handler          | Read the username from the request context.                            |

The table below lists the outcomes.

| Condition                                         | Result                                                        |
| :------------------------------------------------ | :------------------------------------------------------------ |
| Valid client certificate                          | Request proceeds with the username set to the certificate CN. |
| No client certificate on a relying-party endpoint | Status `401`, unless `disable_authentication` is `true`.      |
| Certificate not signed by a CA in the trust store | The TLS handshake fails.                                      |
| CN ends with `*`                                  | Status `401`. Wildcard usernames are rejected.                |
| Certificate has no CN                             | Status `401`.                                                 |
| CN is not valid UTF-8                             | Status `401`.                                                 |

Client certificates must meet these requirements:

- The certificate is signed by a CA in the client CA trust store.
- The Subject field contains a Common Name.
- The certificate is within its validity period.

The CN is any UTF-8 string. The server recommends a value such as `ewqwe-client-01`.

### Test client certificate

The included test client certificate has the Subject `CN=user1.acme.com` and the Issuer `CN=acme.com`. Use it to send a request to a relying-party endpoint during development.

## The x509_san_dns client identifier

For the HAIP profile, the server builds the `client_id` value as `x509_san_dns:<san_dns_name>`. The server reads `san_dns_name` from the DNS subject alternative name (SAN) of the leaf certificate in `openid4vp_config.haip_config.x509_cert_path`. The same `client_id` value appears in the signed authorization request.

The wallet checks that the host part of the `client_id` matches the DNS SAN of the server certificate. The server certificate must therefore carry the DNS name that the wallet uses to reach the server.

The included test TLS certificate has these SAN entries: `DNS:demo.ewqwe.local`, `DNS:localhost`, and `IP:127.0.0.1`. With this certificate the server builds the client identifier `x509_san_dns:demo.ewqwe.local`.

## Test certificates

> [!WARNING]
> Never use the test certificates in production.

The test certificates are in the `certificates/` directory at the repository root.

### TLS certificates

The TLS certificates are in `certificates/tls/`.

| File                         | Purpose                                                              |
| :--------------------------- | :------------------------------------------------------------------- |
| `ewqwe.server.cert.pem`      | Server TLS certificate. CN `ewqwe.acme.com`.                         |
| `ewqwe.server.key.pem`       | Server TLS private key.                                              |
| `ewqwe.server.fullchain.pem` | Server leaf certificate and CA chain, used for the JAR `x5c` header. |
| `ewqwe.ca.pem`               | CA chain. The tests also use it as the client CA chain.              |
| `ewqwe.root.key.pem`         | Root CA private key.                                                 |
| `ewqwe.user1.cert.pem`       | Client certificate for mutual TLS. CN `user1.acme.com`.              |
| `ewqwe.user1.key.pem`        | Client private key that matches `ewqwe.user1.cert.pem`.              |
| `ewqwe.user2.cert.pem`       | A second client certificate.                                         |

The server certificate carries the SAN entries `DNS:demo.ewqwe.local`, `DNS:localhost`, and `IP:127.0.0.1`.

### Attestation signing certificates

The attestation signing certificates are in `certificates/signer/`.

| File                              | Purpose                                              |
| :-------------------------------- | :--------------------------------------------------- |
| `ewqwe.signer.leaf.cert.pem`      | Attestation issuer certificate. CN `ewqwe.acme.com`. |
| `ewqwe.signer.leaf.key.pem`       | Attestation issuer private key.                      |
| `ewqwe.signer.leaf.fullchain.pem` | Attestation issuer certificate and CA chain.         |
| `ewqwe.signer.ca.pem`             | Attestation issuer CA certificate.                   |
| `ewqwe.signer.ca.key.pem`         | Attestation issuer CA private key.                   |

### Credential issuer CA certificates

The trusted credential issuer CA certificates are in `certificates/issuers_cas/`. The directory holds the age-verification issuer CA, the EU PID issuer CA, and public root CAs such as `dc4eu.pem`, `isrg_root_x1.pem`, and `isrg_root_x2.pem`.

## Disabling authentication

The `disable_authentication` key turns off the client certificate requirement. When the value is `true`, the `EnsureAuth` middleware inserts `disabled_authentication_user` as the authenticated username on every request that has no certificate. The default username is `test`.

> [!WARNING]
> The `disable_authentication = true` setting removes authentication from every relying-party endpoint. Use it only for local development and tests.
