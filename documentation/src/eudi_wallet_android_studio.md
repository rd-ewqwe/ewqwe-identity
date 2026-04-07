# Installing the EUDI Android Wallet on Android Studio

## What is the EUDI Wallet?

The **EUDI Wallet** (European Digital Identity Wallet) is the official reference implementation of the EU Digital Identity Wallet, developed by the European Commission. It allows EU citizens to securely store and present digital credentials such as:

- **EU Personal Identification Data (PID)** - Digital identity credentials
- **Mobile Driving Licence (mDL)** - ISO 18013-5 compliant digital driving licences
- **Age verification attestations** - Proof of age without revealing exact birth date

The wallet implements key standards including **OpenID4VP** (for verifiable presentations), **OpenID4VCI** (for credential issuance), and **ISO 18013-5** (for mDL). It serves as the reference implementation for testing interoperability with Relying Parties and Credential Verifiers.

The [EUDI Android Wallet source code](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui) is open source and available on GitHub.

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

- [Prerequisites](#prerequisites)
- [Installing Android Studio](#installing-android-studio)
- [Cloning and Building the EUDI Wallet](#cloning-and-building-the-eudi-wallet)
- [Setting Up an Android Emulator](#setting-up-an-android-emulator)
- [Running on a Physical Device](#running-on-a-physical-device)
- [Enabling Developer Mode on Android](#enabling-developer-mode-on-android)
- [Installing External APKs](#installing-external-apks)
- [Debugging a Webapp with Android Studio](#debugging-a-webapp-with-android-studio)
- [Troubleshooting](#troubleshooting)
- [References](#references)

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

### Step 1: Clone the Repository

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
|--------|-------------|
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

   ```
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
|----------|----------|
| Device not appearing | Ensure USB debugging is enabled; try different USB cable |
| Slow connection | Use USB 3.0 port; close unnecessary DevTools panels |
| Cannot inspect HTTPS | Ensure valid/trusted certificates or use `--ignore-certificate-errors` |
| Emulator debugging | Use `10.0.2.2` instead of `localhost` to access host machine |

> **Sources**:
>
> - [Chrome Developers - Remote Debugging on Android](https://developer.chrome.com/docs/devtools/remote-debugging/)
> - [Android Developers - Debug Your Layout](https://developer.android.com/studio/debug/layout-inspector)

## Troubleshooting

### Common Issues

#### Gradle Sync Failed

```
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
