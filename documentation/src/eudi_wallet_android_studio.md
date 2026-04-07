# Installing the EUDI Android Wallet on Android Studio

## What is the EUDI Wallet?

The **EUDI Wallet** (European Digital Identity Wallet) is the official reference implementation of the EU Digital Identity Wallet, developed by the European Commission. It allows EU citizens to securely store and present digital credentials such as:

- **EU Personal Identification Data (PID)** - Digital identity credentials
- **Mobile Driving Licence (mDL)** - ISO 18013-5 compliant digital driving licences
- **Age verification attestations** - Proof of age without revealing exact birth date

The wallet implements key standards including **OpenID4VP** (for verifiable presentations), **OpenID4VCI** (for credential issuance), and **ISO 18013-5** (for mDL). It serves as the reference implementation for testing interoperability with Relying Parties and Credential Verifiers.

The [EUDI Android Wallet source code](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui) is open source and available on GitHub.

> **Important: EUDI Wallet vs. Age Verification App**
>
> There are **two separate wallet applications** with different purposes:
>
> | Wallet | Profile | Client ID Schemes | Credentials | URL Scheme |
> | ------- | -------- | ------------------ | ------------ | ----------- |
> | **EUDI Wallet** | HAIP (High Assurance) | `x509_san_dns`, `x509_hash` | PID, mDL, various | `eudi-openid4vp://` |
> | **Age Verification App** | Annex A | `redirect_uri` | Proof of Age only | `av://` |
>
> The **EUDI Wallet** (this guide) does **not** support the `redirect_uri` client ID scheme mandated by the EU Age Verification Profile (Annex A). To test Annex A-compliant age verification, you need the [Age Verification App](./av_wallet_android_studio.md) instead.
>
> **For testing with the EUDI Wallet**, your Relying Party must:
>
> 1. Use the `x509_san_dns` or `x509_hash` client ID scheme
> 2. Sign Authorization Requests as JWTs with an `x5c` certificate chain in the header
> 3. Add your verifier's root CA certificate to the wallet's [Reader Trust Store](#adding-trusted-verifier-certificates)
>
> See the [User Journey](./user-journey.md) for a detailed comparison of both profiles.

## ewQwe Demo Setup

> **⚠️ FOR TESTING ONLY** — The ewQwe fork uses debug-only CA pinning to trust the ewQwe
> self-signed test certificates. These modifications **must not** be used in production.
> Release builds use the standard EUDI trust store with no overrides.

This section describes how to run the **ewQwe fork** of the EUDI Wallet together with the ewQwe Relying Party Demo Webapp for end-to-end HAIP testing on a local Android emulator.

**Repository**: <https://github.com/bgrieder/android-eudi-haip-wallet/>

### ewQwe Demo Prerequisites

- Android Studio installed (see [Installing Android Studio](#installing-android-studio))
- ewQwe Demo Webapp running (see [Demo Webapp](./demo_webapp.md))
- ewQwe Credential Verifier running on port 9443

### Step 1: Clone the Repository

```bash
git clone https://github.com/bgrieder/android-eudi-haip-wallet.git
cd android-eudi-haip-wallet
```

### Step 2: Create and Start the Emulator

Run the provided setup script from the project root. The script requires a rootable (Google APIs, non-Play Store) system image:

```bash
./start_ewqwe_eudi_emulator.sh
```

**What this script does:**

1. Installs the correct Android system image if not already present
2. Creates a custom AVD named `EUDI_Dev_Device` (Pixel 6 Pro profile)
3. Enables hardware keyboard passthrough for typing on the emulator
4. Starts the emulator with `-writable-system` (required for host mapping)
5. **Maps `demo.ewqwe.local` inside the emulator to your machine's LAN IP address** — this allows the wallet to reach your local dev servers

> To map `demo.ewqwe.local` manually (if you already have a running emulator):
>
> ```bash
> adb root && adb shell "echo '10.0.2.2  demo.ewqwe.local' >> /etc/hosts"
> ```

> **Physical device?** The emulator's `10.0.2.2` alias is emulator-only. For a physical Android
> device on your LAN, use [Local Network DNS Setup](#local-network-dns-setup) instead.

### Step 3: Build and Run the App

1. Open the project in Android Studio
2. Select the `app` module and the `EUDI_Dev_Device` emulator
3. Click **Run** (▶️) to deploy and start the EUDI Wallet app

### Step 4: Initialize Documents

Once the app is running on the emulator:

1. Follow the on-screen prompts to create a **PIN code**
2. Tap the **"+"** icon and select **"Add a Document from List"**
3. Select both **"mDL (MSO MDOC)"** and **"PID (MSO MDOC)"** from the `https://euidw.dev` issuer
4. When prompted for the country, select **"Form EU"**
5. Fill in the test form, submit it, and authorize the issuance

### Step 5: Open the Relying Party Demo Webapp

1. Open **Chrome** on the Android emulator
2. Navigate to `https://demo.ewqwe.local:5174`
3. Proceed past the certificate warning (expected — the demo uses a self-signed certificate)
4. The Demo Webapp should load

### Step 6: Request HAIP Credentials

1. From the webapp, select a HAIP credential type (mDL or National ID) and initiate a request
2. This triggers a deep link that opens the EUDI Wallet
3. The wallet validates the certificate chain against the ewQwe CA bundled in `assets/ewqwe_dev_cas/` and proceeds
4. Approve the credential sharing in the wallet
5. The webapp displays the verified claims

### Debug Certificate Trust (Technical Details)

The ewQwe fork uses **debug-only CA pinning** instead of trust-all bypasses. In `DEBUG` builds only:

| Mechanism | File | What it does |
| --------- | ---- | ------------ |
| **CA-pinned TLS** | `network-logic/.../di/NetworkModule.kt` | Loads `assets/ewqwe_dev_cas/*.pem` into a `KeyStore` and builds an `X509TrustManager` from it. Standard hostname verification still applies. No-op in `RELEASE` builds. |
| **CA-pinned Reader Trust Store** | `core-logic/.../di/LogicCoreModule.kt` | Passes the same CA certificates as trust anchors to `ReaderTrustStore.getDefault()`. JAR `x5c` chains are validated against these CAs. No-op in `RELEASE` builds; production trust anchors from `WalletCoreConfigImpl.configureReaderTrustStore()` apply instead. |

**Adding a new developer CA:** drop a `.pem` or `.crt` file into
`resources-logic/src/main/assets/ewqwe_dev_cas/` and rebuild — no code change required.

---

## Local Network DNS Setup

The `x509_san_dns` three-way binding rule means `demo.ewqwe.local` must be
DNS-resolvable on every device used for testing. There are two approaches:

### Option A — Android Emulator (easiest)

The emulator uses `10.0.2.2` as its alias for the host machine. The setup script injects the
mapping automatically; to do it manually:

```bash
adb root && adb shell "echo '10.0.2.2  demo.ewqwe.local' >> /etc/hosts"
```

### Option B — Physical Android Device via `dnsmasq` (LAN)

`dnsmasq` turns your dev Mac into a local DNS server that resolves `demo.ewqwe.local` to your
machine's LAN IP for any device on the same Wi-Fi network.

**1. Install and configure dnsmasq:**

```bash
brew install dnsmasq

# Replace <YOUR-LAN-IP> with your machine's LAN address (e.g. 192.168.1.42)
# Find it with: ipconfig getifaddr en0
echo "address=/demo.ewqwe.local/<YOUR-LAN-IP>" >> /opt/homebrew/etc/dnsmasq.conf

sudo brew services restart dnsmasq
```

**2. Verify it works on your Mac:**

```bash
dig @127.0.0.1 demo.ewqwe.local
# Should resolve to your LAN IP
```

**3. Point the Android device at your Mac's DNS:**

On the Android device: **Settings → Wi-Fi → long-press your network → Modify network →
Advanced → IP settings: Static** then set **DNS 1** to `<YOUR-LAN-IP>`.

> No root access required on the Android device. Any device on your Wi-Fi that uses this DNS
> setting will resolve `demo.ewqwe.local` correctly.

### Custom Hostnames

If you regenerate the test certificates with a different DNS SAN (e.g. your machine's mDNS name),
update `public_root_url` in
[`credential_verifier/credential-server.toml`](../credential_verifier/credential-server.toml) to
match, and use the same hostname in your DNS setup.

---

## Quick Start: Download APK Directly (No Build Required)

You don't need to build the EUDI Wallet from source. The easiest way to install it is to download the pre-built APK directly from GitHub using Chrome on the Android emulator:

1. **Install Android Studio** and create an emulator (see [Setting Up an Android Emulator](#setting-up-an-android-emulator))
2. **Enable Developer Mode on the emulator** (see [Enabling Developer Mode](#enabling-developer-mode-on-android)) - this is required before installing external APKs
3. **Open Chrome** on the emulator
4. Navigate to [EUDI Wallet Releases](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/releases)
5. Download the latest APK (e.g., `app-demo-debug.apk`)
6. Open the downloaded file and tap **Install**
7. If prompted about "unknown sources", allow Chrome to install apps

> **Note**: Use the `demo` variant for testing with the EU demo infrastructure, or `dev` for development environments.

---

This guide also explains how to build the wallet from source if you need to modify the code or debug the application.

## Table of Contents

- [ewQwe Demo Setup](#ewqwe-demo-setup)
- [Local Network DNS Setup](#local-network-dns-setup)
- [HAIP Profile Requirements](#haip-profile-requirements)
- [Prerequisites](#prerequisites)
- [Installing Android Studio](#installing-android-studio)
- [Cloning and Building the EUDI Wallet](#cloning-and-building-the-eudi-wallet)
- [Setting Up an Android Emulator](#setting-up-an-android-emulator)
- [Running on a Physical Device](#running-on-a-physical-device)
- [Enabling Developer Mode on Android](#enabling-developer-mode-on-android)
- [Installing External APKs](#installing-external-apks)
- [Debugging a Webapp with Android Studio](#debugging-a-webapp-with-android-studio)
- [Viewing EUDI Wallet Logs](#viewing-eudi-wallet-logs)
- [Adding Trusted Verifier Certificates](#adding-trusted-verifier-certificates)
- [Troubleshooting](#troubleshooting)
- [References](#references)

## HAIP Profile Requirements

The EUDI Wallet implements the **High Assurance Interoperability Profile (HAIP)**, which is more restrictive than the Annex A profile used by the Age Verification App. Your Relying Party must meet these requirements to work with the EUDI Wallet:

### 1. Client ID Scheme: `x509_san_dns` or `x509_hash`

The EUDI Wallet only accepts these client identifier schemes:

| Scheme | Format | Trust Verification |
| ------- | ------- | ------------------ |
| `x509_san_dns` | `x509_san_dns:<DNS>` | Verifier's certificate must have a `dNSName` SAN matching the client ID (e.g. `x509_san_dns:demo.ewqwe.local` for the demo certs) |
| `x509_hash` | `x509_hash:sha-256:base64url_encoded_hash` | Verifier's certificate must match the hash |

The **`redirect_uri`** scheme from Annex A is **not supported** by the EUDI Wallet.

#### The Three-Way Binding Constraint (`x509_san_dns`)

When using `x509_san_dns`, the wallet unconditionally enforces three conditions that form a
transitive equality chain:

| Property | Must equal | Enforced by |
| -------- | ---------- | ----------- |
| `client_id` bare value (e.g. `demo.ewqwe.local`) | A `dNSName` entry in the **leaf certificate** SAN of the JAR's `x5c` header | `RequestAuthenticator` in `eudi-lib-jvm-openid4vp-kt` |
| `response_uri` **hostname** | The `client_id` bare value | `RequestObjectValidator` in `eudi-lib-jvm-openid4vp-kt` |
| TLS server cert SAN | The `response_uri` hostname | Standard TLS hostname verification |

By transitivity: **the hostname where the wallet posts the VP Token must be a DNS SAN on the JAR
signing certificate.**

> **`response_uri` vs `request_uri`** — These are two distinct URLs that happen to share the same
> hostname in this project:
>
> - `request_uri`: the endpoint the wallet **fetches** the signed Authorization Request (JAR) from
> - `response_uri`: the endpoint the wallet **posts the VP Token to** (`direct_post` / `direct_post.jwt`)
>
> The host-match check applies to `response_uri`, not `request_uri`.

Both checks live in the **upstream Maven library** `eudi-lib-jvm-openid4vp-kt` — they cannot be
bypassed through wallet application code. The practical consequence for local network testing is
that `demo.ewqwe.local` must be DNS-resolvable on every test device.
See [Local Network DNS Setup](#local-network-dns-setup) for options.

### 2. Signed Authorization Request (JAR)

All Authorization Requests must be signed JWTs. The JWT header must include:

- `alg`: Signing algorithm (e.g., `ES256` for P-256 ECDSA)
- `x5c`: X.509 certificate chain as an array of base64-encoded certificates (leaf first)
- `kid`: Key identifier (typically the certificate's thumbprint)

Example JWT header:

```json
{
  "alg": "ES256",
  "typ": "oauth-authz-req+jwt",
  "x5c": [
    "MIIBtjCCAVygAwIBAgIUEo...",  // Leaf certificate
    "MIIBxjCCAWygAwIBAgIUAb..."   // Intermediate CA
  ],
  "kid": "7SJZ5d9..."
}
```

### 3. Response Mode: `direct_post.jwt`

The EUDI Wallet uses `response_mode=direct_post.jwt`, meaning the VP Token is wrapped in a signed JWT before being POSTed to the `response_uri`. Your RP must be able to unwrap and verify this JWT.

### 4. Reader Trust Store

The **root CA** that signed your verifier's certificate must be present in the wallet's Reader Trust Store. The EUDI Wallet comes pre-configured with EU PID issuer CAs, but does not include public CAs like Let's Encrypt by default.

If your verifier uses a Let's Encrypt certificate or a custom CA, you must [rebuild the wallet with your root CA](#adding-trusted-verifier-certificates).

### Why These Requirements?

The HAIP profile is designed for **high-assurance credentials** like PID and mDL, where:

- The verifier's identity must be cryptographically proven (via certificate chain)
- Trust is established through a pre-defined set of trusted CAs
- Credential data requires stronger protection (JWT-wrapped responses)

For age verification scenarios where these high-assurance requirements are not necessary, use the [Age Verification App](./av_wallet_android_studio.md) with the simpler Annex A profile.

## Prerequisites

Before you begin, ensure you have:

- **macOS** (Sonoma or later recommended) or **Windows 10/11** or **Linux**
- At least **16 GB of RAM** (recommended for running emulators)
- At least **20 GB of free disk space** for Android Studio, SDKs, and emulators
- A stable internet connection for downloading SDKs and dependencies
- **JDK 21** (Android Studio will manage this, but external builds may require it)

### Minimum Device Requirements for EUDI Wallet

The EUDI Android Wallet requires:

- **API level 29 (Android 10)** or higher

## Installing Android Studio

Android Studio is the official IDE for Android development, provided by Google. It includes everything you need to build, test, and debug Android applications. It runs on **macOS**, **Windows**, and **Linux**.

### Step 1: Download Android Studio

1. Visit the official [Android Studio download page](https://developer.android.com/studio)
2. Click **Download Android Studio**
3. Accept the terms and conditions
4. Choose the appropriate version for your operating system:

**macOS:**

- **Mac with Apple chip** (M1, M2, M3, M4 - all Macs since late 2020)
- **Mac with Intel chip** (older Macs)

**Windows:**

- Download the `.exe` installer (64-bit recommended)

**Linux:**

- Download the `.tar.gz` archive for your architecture

### Step 2: Install Android Studio

#### macOS

1. Open the downloaded `.dmg` file
2. Drag **Android Studio** to the **Applications** folder
3. Launch Android Studio from the Applications folder
4. If prompted with a security warning, click **Open**

#### Windows

1. Run the downloaded `.exe` installer
2. Follow the installation wizard
3. Choose installation location (default is recommended)
4. Select whether to import previous settings

#### Linux

1. Extract the `.tar.gz` archive:

   ```bash
   tar -xzf android-studio-*.tar.gz
   ```

2. Move to `/opt` (optional but recommended):

   ```bash
   sudo mv android-studio /opt/
   ```

3. Run the studio script:

   ```bash
   /opt/android-studio/bin/studio.sh
   ```

4. Optionally create a desktop entry via **Tools → Create Desktop Entry**

### Step 3: Complete Setup Wizard (All Platforms)

1. Follow the Setup Wizard:
   - Choose **Standard** installation for most users
   - Accept license agreements for SDK components
   - Wait for the SDK and additional components to download

### Step 4: Verify Installation

After installation completes:

1. Android Studio opens to the Welcome screen
2. You should see options like "New Project", "Open", and "More Actions"
3. The Android SDK is installed at:
   - **macOS**: `~/Library/Android/sdk`
   - **Windows**: `%LOCALAPPDATA%\Android\Sdk`
   - **Linux**: `~/Android/Sdk`

> **Source**: [Android Developers - Install Android Studio](https://developer.android.com/studio/install)

## Cloning and Building the EUDI Wallet

### Step 1: Clone the wallet Repository

```bash
git clone https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui.git
cd eudi-app-android-wallet-ui
```

### Step 2: Open in Android Studio

1. Launch Android Studio
2. Click **Open**
3. Navigate to the cloned `eudi-app-android-wallet-ui` folder
4. Click **Open**
5. Wait for Gradle sync to complete (this may take several minutes on first run)

### Step 3: Select Build Variant

The EUDI Wallet has different build configurations:

**Product Flavors:**

- `Dev` - Connects to development environment services
- `Demo` - Connects to demo environment services

**Build Types:**

- `Debug` - Full logging enabled (recommended for development)
- `Release` - No logging (production-ready)

To select a build variant:

1. Go to **Build → Select Build Variant**
2. In the Build Variants panel, find the `:app` module
3. Click the dropdown under "Active Build Variant"
4. Select your preferred variant (e.g., `demoDebug` for testing)

### Step 4: Build the Project

1. Go to **Build → Make Project** (or press `Cmd + F9`)
2. Wait for the build to complete
3. Check the Build output window for any errors

> **Source**: [EUDI Wallet - How to Build](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/blob/main/wiki/how_to_build.md)

## Setting Up an Android Emulator

An Android emulator allows you to run Android apps on your Mac without a physical device.

### Step 1: Open Virtual Device Manager

1. In Android Studio, click **More Actions** on the Welcome screen
   - Or go to **Tools → Device Manager** if a project is open
2. Click **Virtual Device Manager**

### Step 2: Create a Virtual Device

1. Click **Create Virtual Device** (or the **+** button)
2. Choose a device definition:
   - Select a phone like **Pixel 7** or **Pixel 8**
   - Devices with the **Play Store icon** (▶️) support Google Play Services
   - For EUDI Wallet, choose a device with Play Store support
3. Click **Next**

### Step 3: Select a System Image

1. Choose an Android version:
   - **API 34** (Android 14) or higher is recommended
   - Ensure the ABI matches your Mac:
     - **arm64-v8a** for Apple Silicon Macs (M1/M2/M3)
     - **x86_64** for Intel Macs
2. Click **Download** if the image isn't already installed
3. Wait for the download to complete, then click **Next**

### Step 4: Configure the Emulator

1. Give your virtual device a name (optional)
2. Adjust advanced settings if needed:
   - **RAM**: 2048 MB minimum, 4096 MB recommended
   - **VM Heap**: 512 MB minimum
   - **Graphics**: Hardware (for better performance)
3. Click **Finish**

### Step 5: Launch the Emulator

1. In the Device Manager, find your virtual device
2. Click the **Play** button (▶️) to start the emulator
3. Wait for Android to boot (first boot takes longer)

> **Source**: [Android Developers - Create and Manage Virtual Devices](https://developer.android.com/studio/run/managing-avds)

## Running on a Physical Device

Running on a physical Android device provides the most accurate testing experience.

### Step 1: Enable Developer Mode

See the [Enabling Developer Mode](#enabling-developer-mode-on-android) section below.

### Step 2: Enable USB Debugging

1. On your Android device, go to **Settings → Developer options**
2. Enable **USB debugging**
3. Optionally enable **Install via USB** for APK installation

### Step 3: Connect Your Device

1. Connect your Android device to your Mac via USB
2. On your Android device, a prompt appears asking to **Allow USB debugging**
3. Check **Always allow from this computer** (optional)
4. Tap **Allow**

### Step 4: Verify Connection

1. In Android Studio, your device should appear in the device dropdown (top toolbar)
2. Alternatively, run in Terminal:

   ```bash
   ~/Library/Android/sdk/platform-tools/adb devices
   ```

3. You should see your device listed

### Step 5: Run the App

1. Select your device from the device dropdown
2. Click **Run** (▶️) or press `Ctrl + R`
3. The app will be installed and launched on your device

> **Source**: [Android Developers - Run Apps on a Hardware Device](https://developer.android.com/studio/run/device)

## Enabling Developer Mode on Android

Developer Mode unlocks advanced options required for app development and APK installation.

### Steps to Enable Developer Mode

1. Open **Settings** on your Android device
2. Scroll down and tap **About phone** (or **About device**)
3. Find **Build number** (may be under **Software information** on Samsung devices)
4. **Tap "Build number" 7 times** in quick succession
5. You'll see messages counting down: "You are now X steps away from being a developer"
6. After 7 taps, you'll see: **"You are now a developer!"**
7. If prompted, enter your device PIN or password

### Access Developer Options

After enabling Developer Mode:

1. Go back to **Settings**
2. Scroll down to find **Developer options** (usually near the bottom)
3. Tap to open and configure developer settings

### Key Developer Options

| Option | Description |
| ------- | ------------ |
| **USB debugging** | Required for connecting to Android Studio |
| **Install via USB** | Allow APK installation over USB |
| **Stay awake** | Screen stays on while charging (useful during development) |
| **Select debug app** | Choose which app to debug |
| **OEM unlocking** | Required for bootloader unlocking (advanced) |

> **Source**: [Android Developers - Configure On-Device Developer Options](https://developer.android.com/studio/debug/dev-options)

## Installing External APKs

You can install APK files (Android Package files) from external sources like GitHub releases.

> **Important**: Before installing external APKs on an emulator or physical device, you must first [enable Developer Mode](#enabling-developer-mode-on-android). This unlocks the ability to install apps from unknown sources.

### Method 1: Download with Chrome on the Emulator (Recommended)

The simplest method - no ADB commands required:

1. Start the Android emulator
2. Enable Developer Mode on the emulator (tap Build Number 7 times in Settings > About)
3. Open **Chrome** on the emulator
4. Navigate to [EUDI Wallet Releases](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/releases)
5. Tap the APK file to download (e.g., `app-demo-debug.apk`)
6. Once downloaded, tap the notification or open from Downloads
7. Tap **Install** when prompted
8. If asked about "Install unknown apps", enable it for Chrome and retry

### Method 2: Using ADB (Android Debug Bridge)

This is the most reliable method for development:

```bash
# Navigate to your platform-tools directory (or add it to PATH)
cd ~/Library/Android/sdk/platform-tools

# Install an APK file
./adb install /path/to/your-app.apk

# For emulator, use the -e flag
./adb -e install /path/to/your-app.apk

# For specific device, use the -s flag with device serial
./adb -s <device_serial> install /path/to/your-app.apk

# Force reinstall (overwrite existing app)
./adb install -r /path/to/your-app.apk
```

### Method 2: Drag and Drop (Emulator Only)

For Android emulators:

1. Start the emulator
2. Download the APK file to your Mac
3. Drag and drop the APK file onto the emulator window
4. The APK will be installed automatically

### Method 3: Using Device File Manager

1. Transfer the APK to your device (via USB, cloud storage, or download)
2. Open a file manager app on your Android device
3. Navigate to the APK file
4. Tap the APK to install
5. If prompted, enable "Install from unknown sources"

### Installing EUDI Wallet APK from GitHub Releases

1. Go to [EUDI Wallet Releases](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/releases)
2. Download the latest APK file (e.g., `app-demo-debug.apk`)
3. Install using one of the methods above

> **Source**: [Android Developers - ADB Commands](https://developer.android.com/tools/adb)

## Debugging a Webapp with Android Studio

You can debug web applications running in Chrome on Android using Chrome DevTools and Android Studio.

### Method 1: Chrome DevTools Remote Debugging

This is the most common method for debugging webapps:

#### Step 1: Enable USB Debugging

1. Enable Developer Mode on your Android device (see above)
2. Enable **USB debugging** in Developer options
3. Connect your device via USB

#### Step 2: Enable Remote Debugging in Chrome

1. Open **Chrome** on your Android device
2. Navigate to your webapp URL
3. On your **Mac**, open Chrome and go to:

   ```text
   chrome://inspect/#devices
   ```

4. Your Android device should appear with open tabs listed
5. Click **Inspect** next to the tab you want to debug
6. Chrome DevTools opens, connected to your mobile Chrome

#### Features Available

- **Elements panel**: Inspect and modify DOM
- **Console**: View logs and run JavaScript
- **Network**: Monitor network requests
- **Sources**: Debug JavaScript with breakpoints
- **Performance**: Profile rendering performance
- **Application**: Inspect storage, service workers, etc.

### Method 2: Android Studio's Chrome Tab Debugging

Android Studio can also connect to Chrome tabs:

1. Connect your Android device
2. In Android Studio, go to **View → Tool Windows → App Inspection**
3. Select your device
4. Choose the Chrome process
5. Use the inspection tools to debug

### Method 3: Debugging WebViews in Native Apps

If your webapp runs inside an Android app's WebView:

1. The app must enable WebView debugging:

   ```java
   WebView.setWebContentsDebuggingEnabled(true);
   ```

2. Connect your device via USB
3. Open `chrome://inspect/#devices` in Chrome on your Mac
4. WebViews appear separately from Chrome tabs
5. Click **Inspect** to debug

### Debugging Tips

| Scenario | Solution |
| --------- | --------- |
| Device not appearing | Ensure USB debugging is enabled; try different USB cable |
| Slow connection | Use USB 3.0 port; close unnecessary DevTools panels |
| Cannot inspect HTTPS | Ensure valid/trusted certificates or use `--ignore-certificate-errors` |
| Emulator debugging | Use `10.0.2.2` instead of `localhost` to access host machine |

> **Sources**:
>
> - [Chrome Developers - Remote Debugging on Android](https://developer.chrome.com/docs/devtools/remote-debugging/)
> - [Android Developers - Debug Your Layout](https://developer.android.com/studio/debug/layout-inspector)

## Viewing EUDI Wallet Logs

When debugging OpenID4VP flows or diagnosing wallet errors, you can inspect the EUDI Wallet's runtime logs using **Logcat** — Android's standard logging system. The easiest approach is to use the **Logcat** tab built into Android Studio (located in the bottom panel): select your emulator from the device dropdown, then filter by the wallet's package name `eu.europa.ec.euidiw` to isolate its output. You can further narrow the results by searching for tags such as `OpenId4Vp`, `PresentationManager`, or `WalletCore`. Alternatively, you can use `adb` from the command line:

```bash
# Stream logs for the EUDI Wallet process only
adb logcat --pid=$(adb shell pidof eu.europa.ec.euidiw)

# Or filter by relevant tags
adb logcat -s "OpenId4VpManager" "PresentationManager" "WalletCore"

# Or grep for wallet-related keywords across all logs
adb logcat | grep -iE "eudi|openid4vp|presentation|mdoc|wallet"
```

> **Tip**: If you installed `adb` via Android Studio, the binary is located at `~/Library/Android/sdk/platform-tools/adb`. Add it to your `PATH` for convenience.

## Adding Trusted Verifier Certificates

When using the `x509_san_dns` client ID scheme for OpenID4VP, the EUDI Wallet validates the verifier's x5c certificate chain against a built-in **Reader Trust Store**. By default, this trust store only contains EU PID Issuer CA certificates (e.g., `pidissuerca02_eu`, `dc4eu`, `r45_staging`). If your verifier uses a certificate signed by a different CA — such as Let's Encrypt — the wallet will reject the request with:

```text
CERTIFICATE_PATH_ERROR: Trust anchor for certification path not found.
Invalid resolution: InvalidJarJwt(cause=Untrusted x5c)
```

To fix this, you must build the wallet from source with your CA's root certificate added to the trust store.

### Step 1: Identify Your Root CA

Determine which root CA signed your verifier's certificate. For a Let's Encrypt certificate, inspect the chain:

```bash
openssl x509 -in your_fullchain.pem -noout -issuer
# issuer= /C=US/O=Let's Encrypt/CN=E7

# The E7 intermediate is signed by ISRG Root X1
```

Let's Encrypt uses two root CAs:

- **ISRG Root X1** (RSA) — signs E-series and R-series intermediates (via cross-sign)
- **ISRG Root X2** (ECDSA) — signs E-series intermediates natively

### Step 2: Download the Root CA Certificates

```bash
# Download ISRG Root X1
curl -s https://letsencrypt.org/certs/isrgrootx1.pem \
  -o resources-logic/src/main/res/raw/isrg_root_x1.pem

# Download ISRG Root X2
curl -s https://letsencrypt.org/certs/isrg-root-x2.pem \
  -o resources-logic/src/main/res/raw/isrg_root_x2.pem
```

Verify the downloaded certificates:

```bash
openssl x509 -in resources-logic/src/main/res/raw/isrg_root_x1.pem -noout -subject -issuer
# subject= /C=US/O=Internet Security Research Group/CN=ISRG Root X1
# issuer= /C=US/O=Internet Security Research Group/CN=ISRG Root X1
```

### Step 3: Update the Reader Trust Store Configuration

Edit the `WalletCoreConfigImpl.kt` for your build flavor (e.g., `demo`):

```text
core-logic/src/demo/java/eu/europa/ec/corelogic/config/WalletCoreConfigImpl.kt
```

Add your root certificates to the `configureReaderTrustStore` call:

```kotlin
configureReaderTrustStore(
    context,
    R.raw.pidissuerca02_cz,
    R.raw.pidissuerca02_ee,
    R.raw.pidissuerca02_eu,
    R.raw.pidissuerca02_lu,
    R.raw.pidissuerca02_nl,
    R.raw.pidissuerca02_pt,
    R.raw.pidissuerca02_ut,
    R.raw.dc4eu,
    R.raw.r45_staging,
    R.raw.isrg_root_x1,   // Let's Encrypt RSA root
    R.raw.isrg_root_x2    // Let's Encrypt ECDSA root
)
```

### Step 4: Build and Install

```bash
./gradlew :app:installDemoDebug
```

This will build and install the updated wallet on your connected emulator or device. The wallet will now accept verifier certificates signed by Let's Encrypt.

> **Note**: If you use a different CA (e.g., your own self-signed root CA), follow the same steps: place your root CA `.pem` file in `resources-logic/src/main/res/raw/` and add its resource reference to `configureReaderTrustStore()`. Only **root CA** certificates need to be added — intermediates are validated through the x5c chain provided in the JAR JWT header.
> **Source**: [EUDI Wallet Configuration Guide](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/blob/main/wiki/configuration.md)

## Troubleshooting

### Common Issues

#### Gradle Sync Failed

```text
Error: Could not find com.android.tools.build:gradle:X.X.X
```

**Solution**:

1. Check your internet connection
2. Go to **File → Invalidate Caches → Invalidate and Restart**
3. Try **File → Sync Project with Gradle Files**

#### Emulator Won't Start

**On Apple Silicon Macs**:

- Ensure you downloaded an ARM64 system image
- Check Rosetta 2 is installed: `softwareupdate --install-rosetta`

**General**:

- Increase RAM allocation in emulator settings
- Close other memory-intensive applications
- Try cold boot: **Device Manager → Right-click device → Cold Boot Now**

#### ADB Device Not Found

```bash
# Restart ADB server
~/Library/Android/sdk/platform-tools/adb kill-server
~/Library/Android/sdk/platform-tools/adb start-server
```

#### EUDI Wallet Build Errors

- Ensure JDK 21 is configured: **Android Studio → Preferences → Build, Execution, Deployment → Build Tools → Gradle → Gradle JDK**
- Try **Build → Clean Project** followed by **Build → Rebuild Project**

## References

### Official Documentation

- [Android Studio Installation Guide](https://developer.android.com/studio/install) - Google
- [Android Virtual Device Manager](https://developer.android.com/studio/run/managing-avds) - Google
- [Configure Developer Options](https://developer.android.com/studio/debug/dev-options) - Google
- [ADB Command Reference](https://developer.android.com/tools/adb) - Google
- [Chrome Remote Debugging](https://developer.chrome.com/docs/devtools/remote-debugging/) - Google

### EUDI Wallet Documentation

- [EUDI Android Wallet Repository](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui) - European Commission
- [EUDI Wallet How to Build Guide](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/blob/main/wiki/how_to_build.md) - European Commission
- [EUDI Wallet Configuration Guide](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/blob/main/wiki/configuration.md) - European Commission

### Additional Resources

- [XDA Developers - Install Android Apps on macOS](https://www.xda-developers.com/how-install-android-apps-macos/) - Guide to running Android apps on Mac
- [EUDI Wallet Architecture Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework) - Technical specifications
