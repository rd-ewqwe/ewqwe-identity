# France Identité Playground Wallet: Installation & Testing Guide

This chapter explains how to install the **France Identité Wallet** from the [EUDIW Playground](https://playground.france-identite.gouv.fr/doc/) and configure it to test the **ISO 18013-7 Annex B (OpenID4VP)** flow with the ewQwe Credential Verifier.

The France Identité Wallet uses deep-link OpenID4VP (Annex B) for all its remote verification flows. It does **not** yet support the W3C Digital Credentials API (Annex C) in production. See the [webapp documentation](../demo_webapp.md#why-w3c-digital-credentials-is-disabled-on-mobile) for the technical background on Annex C status.

## Overview

The France Identité Wallet is the official French digital identity wallet, developed by the French government. It supports:

| Protocol | Status |
|----------|--------|
| **OpenID4VP 1.0 (Annex B)** — Deep-link / cross-device via `openid4vp://` | ✅ Production |
| **ISO 18013-7 Annex C (W3C DC API)** — `navigator.credentials.get()` | ❌ Not supported in production — `openid4vp` protocol identifier not yet recognised by the wallet's DC API handler |
| **ISO 18013-5 (QR Code + BLE)** — Proximity verification | ✅ Supported |
| **Credential Format** | `mdoc` only (ISO 18013-5 mDoc) |

> **Important:** This guide covers **Annex B (OpenID4VP)** flows only — the wallet is invoked via `openid4vp://` deep links or QR code scanning. Annex C (W3C DC API) is not functional with any production EUDI wallet as of mid-2026.

## Prerequisites

Before you begin, ensure you have:

- An **Android device** (physical or emulator) running Android 9+ (API 28+)
- A **Google account** to access the Play Store (if using the Play Store build)
- A **computer** running the ewQwe Credential Verifier with a **publicly reachable URL** or a **local network setup**
- **Credentials** provisioned in the wallet (see [Provisioning Test Credentials](#provisioning-test-credentials) below)

## Step 1: Obtain the Wallet

1. Visit the [EUDIW Playground — France Identité Wallet details](https://playground.france-identite.gouv.fr/doc/marketplace/wallets/france-identite/)
2. Click the **Wallet** link in the Marketplace table
3. Look for APK download links or contact France Identité through the playground

## Step 2: Provision Test Credentials

The France Identité Wallet requires **provisioned credentials** (mDoc format) to present during verification. 

The PARTENAIRES - France Identité Wallet can obtain generate test credentials through the French government's identity system:

1. Open the wallet app
2. Select **"Obtenir mon identité"** (Get my identity)
3. Follow the FranceConnect+ flow to link your French identity
4. The wallet will receive an mDoc PID (Personal Identification Data) containing age-related claims

### Step 3: Activate the QR Code

1. Go to `notifications`
2. Select `Accédez à plus de services` and `Activer maintenant`
3. Unlock the wallet


### Step 4: Request credentials from the PID (National ID)

The following claims to be supported by the PIDs (eu.europa.ec.eudi.pid.1) of the wallet :
- family_name
- given_name
- birth_date
- portrait
- nationality

Selecting usupported claims (such as `sex`) will return `Wallet error (§8.5) — access_denied: wallet did not have the requested credentials to satisfy the authorization request`

The document is an MSO DOC (Mobile Self-Organisation Document) that must be requested using OpenID4VP (no W3C DC / Annex C support).
Both the same device and cross-device flows are supported.


## Debugging

Using `adb`:

```bash
adb -d logcat --pid $(adb -d shell pidof fr.gouv.franceidentite.partenaires)
```

## References

- [France Identité Wallet on Google Play](https://play.google.com/store/apps/details?id=fr.gouv.interieur.franceidentite)
- [EUDIW Playground — France Identité Details](https://playground.france-identite.gouv.fr/doc/marketplace/wallets/france-identite/)
- [EUDIW Playground Documentation](https://playground.france-identite.gouv.fr/doc/)
- [EUDIW Playground Marketplace](https://playground.france-identite.gouv.fr/doc/marketplace/)
- [ISO/IEC 18013-7 (Annex B)](https://www.iso.org/standard/69086.html) — Mobile Driver Licence – Part 7: Annex B
- [France Identité Wallet GitHub (source)](https://github.com/france-identite/Android-wallet)
- [Documentation: Annex B vs HAIP Comparison](./annex_b_vs_haip.md)
