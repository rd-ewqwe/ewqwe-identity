# Installing the Age Verification App on Android Studio

## What is the Age Verification App?

The **Age Verification (AV) App** is the official wallet application for the [EU Age Verification Solution](https://ageverification.dev/), developed under the EU Digital Identity framework. It is purpose-built for **age verification only**, implementing the [EU Age Verification Profile (Annex A)](https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/).

The AV App allows users to:

- **Obtain Proof of Age attestations** — via document scanning (NFC passport) or online issuance
- **Present proof of age** — to Relying Parties requesting age verification
- **Preserve privacy** — only reveals whether the user meets an age threshold, not their exact birth date

The AV App is a **fork of the EUDI Wallet** but configured specifically for the Annex A profile, with different trust settings, client ID schemes, and URL schemes.

The [AV App Android source code](https://github.com/eu-digital-identity-wallet/av-app-android-wallet-ui) is open source and available on GitHub.

> **Important: Age Verification App vs. EUDI Wallet**
>
> These are **two separate wallet applications** with fundamentally different profiles:
>
> | Feature | Age Verification App | EUDI Wallet |
> |---------|---------------------|-------------|
> | **Profile** | Annex A (Age Verification) | HAIP (High Assurance) |
> | **Client ID Scheme** | `redirect_uri` | `x509_san_dns`, `x509_hash` |
> | **JAR (Signed Requests)** | Not required | Required (JWT with `x5c` header) |
> | **URL Schemes** | `av://`, `avsp://`, `openid4vp://` | `eudi-openid4vp://`, `openid4vp://` |
> | **Credentials** | Proof of Age only | PID, mDL, various |
> | **Response Mode** | `direct_post` | `direct_post.jwt` |
> | **LoA** | Substantial | High |
> | **PAR / DPoP** | Disabled | Supported |
>
> If your Relying Party targets the **EUDI Wallet** using `x509_san_dns` with signed JARs, see the [EUDI Wallet guide](./eudi_wallet_android_studio.md) instead.

## Quick Start: Download APK Directly (No Build Required)

The easiest way to install the AV App is to download the pre-built APK:

1. **Install Android Studio** and create an emulator (see [EUDI Wallet guide — Setting Up an Android Emulator](./eudi_wallet_android_studio.md#setting-up-an-android-emulator))
2. **Enable Developer Mode on the emulator** (see [EUDI Wallet guide — Enabling Developer Mode](./eudi_wallet_android_studio.md#enabling-developer-mode-on-android))
3. **Open Chrome** on the emulator
4. Navigate to [AV App Releases](https://github.com/eu-digital-identity-wallet/av-app-android-wallet-ui/releases)
5. Download the latest APK (e.g., `app-dev-debug.apk`)
6. Open the downloaded file and tap **Install**

> **Note**: Use the `dev` variant for testing with the development infrastructure, or `demo` for the demo environment. Both flavors support `redirect_uri` client ID scheme.

---

## Annex A Profile: What Your RP Needs to Know

The AV App implements the **Annex A profile**, which is significantly simpler than the HAIP profile used by the EUDI Wallet. Here are the key implications for your Relying Party:

### Client ID Scheme: `redirect_uri`

Per [Annex A Section A.5](https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/#a5-proof-of-age-attestation-presentation), the client identifier scheme **MUST** be `redirect_uri`:

> "The client identifier scheme MUST be `redirect_uri` followed by the `response_uri`"

This means:

- **No signed JAR required** — the Authorization Request is sent as plain query parameters
- **No x5c certificate chain** — the wallet identifies the RP by its redirect URI, not a certificate
- **No Reader Trust Store modification** — you do not need to add your CA to the wallet's trust store
- **Simpler implementation** — no JWT signing infrastructure needed

The `client_id` in your Authorization Request must be the literal `redirect_uri:` prefix followed by the `response_uri`:

```
client_id=redirect_uri:https://your-rp.example.com/openid4vp/callback
response_uri=https://your-rp.example.com/openid4vp/callback
```

### URL Schemes for Same-Device Flow

The AV App registers the following URL schemes for deep-linking (same-device flow):

| Scheme | Variable | Purpose |
|--------|----------|---------|
| `av://` | `AV_SCHEME` | Primary AV App scheme |
| `avsp://` | `AVSP_SCHEME` | AV Service Provider scheme |
| `openid4vp://` | `OPENID4VP_SCHEME` | Standard OpenID4VP scheme |
| `eudi-openid4vp://` | `EUDI_OPENID4VP_SCHEME` | EUDI-compatible scheme |
| `mdoc-openid4vp://` | `MDOC_OPENID4VP_SCHEME` | mDoc presentation scheme |

For same-device flows, construct a deep link URL using one of these schemes:

```
av://?client_id=redirect_uri:https://rp.example.com/cb&response_uri=https://rp.example.com/cb&...
```

### Response Mode: `direct_post`

The AV App uses `response_mode=direct_post` (not `direct_post.jwt` as in HAIP). The wallet POSTs the VP Token directly to the `response_uri` as plain form parameters — not wrapped in a JWT.

### Credential Format

The AV App works with:

- **Document type**: `eu.europa.ec.av.1` (Age Verification namespace)
- **Credential format**: mDoc (ISO 18013-5 / CBOR encoded)
- **Key claim**: `age_over_18` (boolean)

### PAR and DPoP: Disabled

Per the Annex A profile, both **Pushed Authorization Requests (PAR)** and **DPoP** are explicitly disabled:

- `parUsage = NEVER`
- `useDPoPIfSupported = false` / `DPoPUsage.Disabled`

## Building from Source

The AV App build process is identical to the EUDI Wallet. Follow the same [Android Studio setup](./eudi_wallet_android_studio.md) guide, but clone the AV App repository instead:

```bash
git clone https://github.com/eu-digital-identity-wallet/av-app-android-wallet-ui.git
cd av-app-android-wallet-ui
```

### Build Variants (Flavors)

The AV App has two build flavors:

| Flavor | Issuer URL | Purpose |
|--------|-----------|---------|
| `dev` | `https://test.issuer.dev.ageverification.dev` | Development / testing |
| `demo` | `https://issuer.ageverification.dev` | Demo environment |

Build and install:

```bash
# Dev flavor
./gradlew :app:installDevDebug

# Demo flavor
./gradlew :app:installDemoDebug
```

## AV App Configuration

The AV App configuration is centralized in `WalletCoreConfigImpl.kt`, with one implementation per flavor:

- `core-logic/src/dev/java/eu/europa/ec/corelogic/config/WalletCoreConfigImpl.kt`
- `core-logic/src/demo/java/eu/europa/ec/corelogic/config/WalletCoreConfigImpl.kt`

### OpenID4VP Configuration (Default)

Both flavors are pre-configured for Annex A:

```kotlin
configureOpenId4Vp {
    withClientIdSchemes(
        listOf(
            ClientIdScheme.RedirectUri  // Annex A mandated scheme
        )
    )
    withSchemes(
        listOf(
            BuildConfig.OPENID4VP_SCHEME,      // openid4vp://
            BuildConfig.EUDI_OPENID4VP_SCHEME,  // eudi-openid4vp://
            BuildConfig.MDOC_OPENID4VP_SCHEME,  // mdoc-openid4vp://
            BuildConfig.AVSP_SCHEME,            // avsp://
            BuildConfig.AV_SCHEME               // av://
        )
    )
    withFormats(
        Format.MsoMdoc.ES256
    )
}
```

### Using the Preregistered Client Scheme (Optional)

If your verifier requires a pre-registered client ID (e.g., for self-signed certificate setups), add the `Preregistered` scheme to the configuration:

```kotlin
const val OPENID4VP_VERIFIER_API_URI = "https://your-verifier.example.com"
const val OPENID4VP_VERIFIER_LEGAL_NAME = "Your Verifier"
const val OPENID4VP_VERIFIER_CLIENT_ID = "your-client-id"

configureOpenId4Vp {
    withClientIdSchemes(
        listOf(
            ClientIdScheme.Preregistered(
                listOf(
                    PreregisteredVerifier(
                        clientId = OPENID4VP_VERIFIER_CLIENT_ID,
                        verifierApi = OPENID4VP_VERIFIER_API_URI,
                        legalName = OPENID4VP_VERIFIER_LEGAL_NAME
                    )
                )
            )
        )
    )
}
```

### Working with Self-Signed Certificates

If your verifier or issuer uses self-signed certificates (development only), see the official [AV App configuration guide](https://ageverification.dev/av-app-android-wallet-ui/docs/configuration/#how-to-work-with-self-signed-certificates) for instructions on configuring a custom `HttpClient` that trusts all certificates.

> **⚠️ Security Warning**: Trusting all certificates disables TLS verification and must **never** be used in production.

## Passport Scanning Issuance

The AV App supports issuing age verification credentials by scanning a physical passport via NFC. This requires a second issuer configuration:

```kotlin
override val passportScanningIssuerConfig: OpenId4VciManager.Config =
    OpenId4VciManager.Config.Builder()
        .withIssuerUrl(issuerUrl = "https://passport.issuer.dev.ageverification.dev")
        .withClientAuthenticationType(
            OpenId4VciManager.ClientAuthenticationType.None(
                clientId = "wallet-dev"
            )
        )
        .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
        .withParUsage(OpenId4VciManager.Config.ParUsage.NEVER)
        .withDPoPUsage(OpenId4VciManager.Config.DPoPUsage.Disabled)
        .build()
```

The passport scanning flow includes face liveness detection and face matching, configured via `faceMatchConfig`.

## Viewing Logs

Logs from the AV App can be viewed using Logcat in Android Studio, identical to the EUDI Wallet. See [Viewing EUDI Wallet Logs](./eudi_wallet_android_studio.md#viewing-eudi-wallet-logs) for instructions.

Filter by the `EudiWallet` tag to see wallet-core events:

```
tag:EudiWallet
```

## Key Differences from the EUDI Wallet (Summary)

| Aspect | AV App (Annex A) | EUDI Wallet (HAIP) |
|--------|-----------------|-------------------|
| **Trust model** | No trust lists needed; `redirect_uri` identifies the RP | Requires root CA in Reader Trust Store |
| **Request signing** | Plain query parameters | Signed JAR with `x5c` certificate chain |
| **Certificate requirements** | Standard HTTPS (any CA) | Specific CA must be trusted by wallet |
| **Implementation complexity** | Low — no JWT signing needed | High — requires PKCS#8 keys, x5c chain |
| **Credential types** | `eu.europa.ec.av.1` (age verification) | `org.iso.18013.5.1.mDL`, PID, various |
| **Privacy features** | Age threshold only (`age_over_18`) | Selective disclosure of any attribute |
| **ZKP support** | Yes (Longfellow circuits) | Not in current reference implementation |
| **DC API** | Enabled | Enabled |

## References

### Official AV App Documentation

- [AV App Android Repository](https://github.com/eu-digital-identity-wallet/av-app-android-wallet-ui) — Source code
- [AV App Installation Guide](https://ageverification.dev/av-app-android-wallet-ui/docs/how_to_build/) — Build instructions
- [AV App Configuration Guide](https://ageverification.dev/av-app-android-wallet-ui/docs/configuration/) — Configuration reference
- [AV App Changelog](https://github.com/eu-digital-identity-wallet/av-app-android-wallet-ui/blob/main/CHANGELOG.md) — Version history

### Age Verification Specifications

- [EU Age Verification Portal](https://ageverification.dev/) — Main project site
- [Annex A — Age Verification Profile](https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/) — Technical specification
- [Architecture and Technical Specifications](https://ageverification.dev/av-doc-technical-specification/docs/architecture-and-technical-specifications/) — Overall architecture

### Issuer Services

- [AV Issuer Service](https://ageverification.dev/av-srv-web-issuing-avw-py/) — Credential issuance service
- [AV Verifier UI](https://ageverification.dev/av-web-verifier-ui/) — Reference verifier implementation
