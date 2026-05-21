# France Identité Playground Wallet: Installation & Testing Guide

This chapter explains how to install the **France Identité Wallet** from the [EUDIW Playground](https://playground.france-identite.gouv.fr/doc/) and configure it to test the **ISO 18013-7 Annex B** flow with the ewQwe Credential Verifier.

## Overview

The France Identité Wallet is the official French digital identity wallet, developed by the French government. It supports:

| Protocol | Status |
|----------|--------|
| **ISO 18013-7 (Annex B)** — Online / remote verification via DC API (W3C Digital Credentials API) | ✅ Supported |
| **OpenID4VP 1.0** — OpenID-based presentation flow | ✅ Supported |
| **ISO 18013-5 (QR Code + BLE)** — Proximity verification | ✅ Supported |
| **Credential Format** | `mdoc` only (ISO 18013-5 mDoc) |

> **Important:** The France Identité Wallet is an **Annex B** wallet that also supports **OpenID4VP 1.0**. This means you can test it in two modes:
> 1. **Annex B / W3C DC API mode** — Uses `navigator.credentials.get()` with ISO DeviceRequest/DeviceResponse (CBOR/HPKE).
> 2. **OpenID4VP mode** — Uses the standard OpenID4VP protocol with `direct_post` or `direct_post.jwt`.

## Prerequisites

Before you begin, ensure you have:

- An **Android device** (physical or emulator) running Android 9+ (API 28+)
- A **Google account** to access the Play Store (if using the Play Store build)
- A **computer** running the ewQwe Credential Verifier with a **publicly reachable URL** or a **local network setup**
- **Credentials** provisioned in the wallet (see [Provisioning Test Credentials](#provisioning-test-credentials) below)

## Step 1: Obtain the Wallet

### Option A: Download from Google Play Store (Recommended)

The France Identité Wallet is available on the Google Play Store:

```bash
# Open the following URL on your Android device:
# https://play.google.com/store/apps/details?id=fr.gouv.interieur.franceidentite
```

Alternatively, search for **"France Identité"** in the Google Play Store and install the app published by **Ministère de l'Intérieur**.

### Option B: Request a Developer Build

If you need debug builds or custom versions for testing:

1. Visit the [EUDIW Playground — France Identité Wallet details](https://playground.france-identite.gouv.fr/doc/marketplace/wallets/france-identite/)
2. Click the **Wallet** link in the Marketplace table
3. Look for APK download links or contact France Identité through the playground

### Option C: Build from Source

The France Identité Wallet source code is available on GitHub. However, this requires a complex build environment:

```bash
# Clone the repository
git clone https://github.com/france-identite/Android-wallet.git
cd Android-wallet

# Build with Gradle
./gradlew assembleDebug
```

See the repository's README for detailed build instructions.

## Step 2: Provision Test Credentials

The France Identité Wallet requires **provisioned credentials** (mDoc format) to present during verification. There are several ways to obtain them:

### Option A: Use the EUDIW Playground Issuers

The [EUDIW Playground Marketplace](https://playground.france-identite.gouv.fr/doc/marketplace/) lists several issuers that can provision credentials to the France Identité Wallet:

| Issuer | Protocols | Formats |
|--------|-----------|---------|
| **Multipaz** | OID4VCI | mdoc |
| **iGrant.io** | OID4VCI 1.0, HAIP 1.0 | mdoc, sd-jwt |
| **Lutralabs** | OID4VCI 1.0 | mdoc, sd-jwt |

**To issue credentials:**

1. Open the France Identité Wallet on your Android device
2. Look for **"Add a credential"** or **"Get a credential"** option
3. Follow the issuer's flow (typically involves scanning a QR code or clicking a deep link)
4. The issuer will provision a test mDoc credential containing age verification claims

### Option B: Use the FranceConnect / France Identité Online Issuance

The France Identité Wallet can obtain real credentials through the French government's identity system:

1. Open the wallet app
2. Select **"Obtenir mon identité"** (Get my identity)
3. Follow the FranceConnect+ flow to link your French identity
4. The wallet will receive an mDoc PID (Personal Identification Data) containing age-related claims

> **Note:** This requires a genuine French identity document (passport or national ID card) and is primarily useful for end-to-end testing with real credentials.

### Option C: Use the ewQwe Test Credential Issuer

The ewQwe project includes tools to issue test credentials in `crates/ewqwe-digital-credential`. For Annex B testing, you need an **mDoc credential** signed by a trusted CA:

```rust
// Example: Issue a test mDoc credential (from ewqwe-digital-credential crate)
use ewqwe_digital_credential::CredentialIssuer;

let issuer = CredentialIssuer::new_test_issuer()?;
let mdoc = issuer.issue_mdoc_mdl(age_over_18 = true)?;
```

You would then need a custom issuance endpoint or OID4VCI service to deliver this credential to the wallet. This is more complex and recommended only if you control the wallet's provisioning.

## Step 3: Add the Verifier's CA Certificate to the Wallet Trust Store

For the **Annex B W3C DC API flow**, the wallet validates the verifier's certificate. You need to install the ewQwe server's CA certificate on the Android device.

### Install as a User CA Certificate

1. **Export the CA certificate** from your ewQwe credential verifier setup:

   ```bash
   # The server CA chain is configured in credential-server.toml:
   # [tls_params]
   # server_ca_chain = "../../certificates/tls/ewqwe.ca.pem"
   
   # Copy the CA certificate to your Android device
   cp ../../certificates/tls/ewqwe.ca.pem /tmp/ewqwe-ca.crt
   ```

2. **Transfer the certificate to your Android device:**
   - Email it to yourself and download on device
   - Use `adb push` if using an emulator:
     ```bash
     adb push /tmp/ewqwe-ca.crt /sdcard/Downloads/ewqwe-ca.crt
     ```

3. **Install the certificate:**
   - Open **Settings → Security → Encryption & credentials → Install a certificate**
   - Select **"CA certificate"**
   - Navigate to the certificate file and select it
   - Confirm installation (you may need to set up a PIN/pattern if not already done)
   - The certificate will appear under **"User credentials"**

### For Android Emulator with Custom Root CA

If using an Android emulator, you may need to install the CA at the system level:

```bash
# Re-root the emulator system image (requires a writable system image)
adb root
adb remount
adb push /tmp/ewqwe-ca.crt /system/etc/security/cacerts/ewqwe-ca.crt
adb reboot
```

> **Note:** For testing purposes with the France Identité Wallet, installing as a **user CA** is usually sufficient. If you encounter certificate validation errors, try the system-level installation.

## Step 4: Configure the Network

### For Physical Device

Ensure the Android device can reach the credential verifier:

1. If the verifier is on your **local network**, use the machine's local IP address:
   - Find your machine's IP: `ifconfig` or `ip addr`
   - Set `public_root_url` in `credential-server.toml`:
     ```toml
     public_root_url = "https://192.168.1.42:9443"
     ```

2. If the verifier is behind a **reverse proxy with a public domain**, use that:
   ```toml
   public_root_url = "https://verifier.example.com"
   ```

3. If using **ngrok** or similar tunneling service:
   ```bash
   ngrok http 9443
   ```
   Then set:
   ```toml
   public_root_url = "https://abc123.ngrok.io"
   ```

### For Android Emulator

The Android emulator can reach the host machine via `10.0.2.2`:

```toml
public_root_url = "https://10.0.2.2:9443"
```

However, the France Identité Wallet's Annex B flow uses the W3C Digital Credentials API, which requires a valid HTTPS connection. You'll need a certificate that the device trusts:

1. **Use a domain name** that resolves to the emulator's host (e.g., via `/etc/hosts` on the host machine)
2. Install the CA certificate as described in [Step 3](#step-3-add-the-verifiers-ca-certificate-to-the-wallet-trust-store)

## Step 5: Start the ewQwe Credential Verifier

```bash
# Navigate to the credential verifier
cd crates/ewqwe-credential-verifier-server

# Update the configuration for France Identité testing
# Edit credential-server.toml:
cat << 'EOF'
public_root_url = "https://YOUR_PUBLIC_URL:9443"

[openid4vp_config]
# For Annex A (OpenID4VP) testing — no HAIP config needed
# transaction_store defaults to in-memory SQLite

# For Annex B / W3C DC API testing
# The DC API flow does not use OpenID4VP transactions
EOF

# Start the server
cargo run --features openssl
```

## Step 6: Test the Flow

### Test 1: OpenID4VP Mode (France Identité Wallet)

The France Identité Wallet supports OpenID4VP 1.0. This is the simplest path:

1. **Start the ewQwe Credential Verifier UI** (if enabled in config):
   - Open `https://YOUR_PUBLIC_URL:9443/` in a browser
   - Log in (see the Verifier UI documentation for credentials)
   - Create a new verification request (QR code)

2. **On the France Identité Wallet:**
   - Open the wallet app
   - Tap **"Scan QR code"** or **"Scanner"**
   - Scan the QR code displayed by the Credential Verifier UI
   - The wallet will evaluate the OpenID4VP request
   - **If the wallet shows a consent dialog**, proceed to authorize
   - **If the wallet shows an error**, check:
     - The wallet needs an mDoc credential provisioned first
     - The credential must contain the requested claims (e.g., `age_over_18`)
     - The wallet must trust the verifier's certificate

3. **Check the result:**
   - The Credential Verifier UI should show a successful verification
   - The verification journal (if enabled) should record the event

### Test 2: W3C Digital Credentials API / Annex B Mode

The Annex B flow uses the W3C Digital Credentials API (`navigator.credentials.get()`) with ISO mDoc DeviceRequest/DeviceResponse wrapping. This requires a **browser-based RP** (not the Credential Verifier UI):

1. **Ensure the ewQwe webapp is running** and configured for the DC API flow:
   ```bash
   cd webapp
   deno task dev
   ```

2. **On the Android device:**
   - Open Chrome (or another browser supporting the Digital Credentials API)
   - Navigate to the ewQwe webapp's RP URL
   - Click **"Verify Age"**
   - The browser should invoke the France Identité Wallet via the DC API

3. **If the DC API flow does not trigger:**
   - The W3C Digital Credentials API may not be available in your browser version
   - The webapp may not have Annex B / DC API support implemented yet
   - See the [Annex B Implementation Plan](./annex_b_implementation_plan.md) for developing this support

## Troubleshooting

### Wallet does not open when scanning QR code

| Cause | Solution |
|-------|----------|
| QR code uses unsupported URL scheme | Ensure the URL scheme matches what France Identité supports (`av://`, `openid4vp://`). For Annex B, it uses the W3C DC API, not a QR code. |
| Wallet not registered for the scheme | Check the wallet's supported URL schemes in its documentation. |
| Deep link not associated with the wallet | Clear default app associations and try again. |

### Certificate validation fails

| Cause | Solution |
|-------|----------|
| CA certificate not installed on device | Follow [Step 3](#step-3-add-the-verifiers-ca-certificate-to-the-wallet-trust-store) |
| Certificate is self-signed and not in trust store | Use a publicly trusted certificate or ensure the CA is properly installed |
| Certificate hostname mismatch | Ensure the `public_root_url` hostname matches the certificate's SAN |
| Android restricts user CA certs (API 24+) | Install as system CA or use a publicly trusted cert |

### Wallet says "No matching credential"

| Cause | Solution |
|-------|----------|
| No mDoc credential provisioned | Follow [Step 2](#step-2-provision-test-credentials) |
| Credential has expired or is invalid | Re-issue the credential |
| Requested claims not in the credential | Check which namespace/claims the credential contains vs. what is requested |
| Credential format mismatch | France Identité uses mDoc only — ensure the request expects `mso_mdoc` format |

### Wallet does not respond to direct_post

| Cause | Solution |
|-------|----------|
| Network connectivity issue | Ensure the device can reach the `response_uri` (check firewalls, NAT, tunneling) |
| TLS handshake failure | Check the verifier's TLS configuration; ensure certificate is trusted |
| Wallet timeout | The wallet may have a short timeout — ensure the server responds promptly |
| `response_uri` not reachable | Use `public_root_url` with a publicly-reachable address |

## References

- [France Identité Wallet on Google Play](https://play.google.com/store/apps/details?id=fr.gouv.interieur.franceidentite)
- [EUDIW Playground — France Identité Details](https://playground.france-identite.gouv.fr/doc/marketplace/wallets/france-identite/)
- [EUDIW Playground Documentation](https://playground.france-identite.gouv.fr/doc/)
- [EUDIW Playground Marketplace](https://playground.france-identite.gouv.fr/doc/marketplace/)
- [ISO/IEC 18013-7 (Annex B)](https://www.iso.org/standard/69086.html) — Mobile Driver Licence – Part 7: Annex B
- [France Identité Wallet GitHub (source)](https://github.com/france-identite/Android-wallet)
- [Documentation: Annex B vs HAIP Comparison](./annex_b_vs_haip.md)
