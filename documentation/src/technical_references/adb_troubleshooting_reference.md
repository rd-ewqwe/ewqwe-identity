# ADB Troubleshooting Reference for Wallet Testing

A comprehensive reference of `adb` commands used when testing digital wallets (EUDI Wallet, France Identité, etc.) with the ewQwe Credential Verifier.

> **Prerequisite**: `adb` is typically located at `~/Library/Android/sdk/platform-tools/adb` on macOS (when installed via Android Studio). Add it to your `PATH` for convenience.

---

## Device & Connection Management

### List Connected Devices

```bash
# List all connected devices/emulators
adb devices

# List only emulator devices
adb devices -e

# List only physical (USB) devices
adb devices -d
```

### Restart ADB Server

```bash
adb kill-server
adb start-server
```

Use when `adb devices` shows no devices even though an emulator is running or a device is connected via USB.

### Connect to a Specific Device

```bash
# Use -s with device serial for single-target commands
adb -s <device_serial> install app.apk

# Use -e for emulator
adb -e install app.apk

# Use -d for physical device (USB)
adb -d install app.apk
```

---

## Installing & Managing APKs

### Install an APK

```bash
# Basic install
adb install /path/to/your-app.apk

# Reinstall (overwrite existing app, keeps data)
adb install -r /path/to/your-app.apk

# Install to emulator
adb -e install /path/to/your-app.apk

# Install to specific device
adb -s <device_serial> install /path/to/your-app.apk
```

### Uninstall an App

```bash
adb uninstall <package_name>

# Example: EUDI Wallet
adb uninstall eu.europa.ec.euidiw

# Example: France Identité
adb uninstall fr.gouv.interieur.franceidentite
```

### List Installed Packages

```bash
# List all packages
adb shell pm list packages

# Filter by keyword
adb shell pm list packages | grep -i eudi
adb shell pm list packages | grep -i france
adb shell pm list packages | grep -i identite
```

---

## W3C Digital Credentials API — Provider Registration

### Check Registered Credential Providers

```bash
# List all credential providers registered with Android CredentialManager
adb shell dumpsys credential
```

**Interpretation**:
- **Empty/missing output** → No wallet has registered as a `CredentialProviderService` with Android's CredentialManager on this device.
- **Populated output** → Wallets that implement a `CredentialProviderService` will appear here. Look for entries under `credential-services`.

> **Important caveat**: Some wallets (including the EUDI Wallet) implement Annex C Sub-protocol B using an **Activity intent filter** on their MainActivity (for actions `androidx.credentials.registry.provider.action.GET_CREDENTIAL` / `androidx.identitycredentials.action.GET_CREDENTIALS`) **instead** of a `CredentialProviderService`. This approach does NOT appear in `dumpsys credential`.
>
> Unfortunately, this Activity-based approach **does not work** with Chrome on Android 14+. Chrome delegates to Android's CredentialManager, which only dispatches to `CredentialProviderService` implementations — not to Activities with intent filters. The DC API request is never received by the wallet.
>
> See [`eudi_wallet_dc_api_analysis.md`](../technical_references/eudi_wallet_dc_api_analysis.md) for the full analysis.

---

## DNS & Network Configuration

### Map `demo.ewqwe.local` to Host Machine (Emulator)

For the Android emulator, the host machine is reachable at `10.0.2.2`. Map the demo domain inside the emulator:

```bash
adb root && adb shell "echo '10.0.2.2  demo.ewqwe.local' >> /etc/hosts"
```

> ⚠️ Requires `adb root` (only works on emulator or rooted devices). The emulator must be started with `-writable-system`.

### Verify the Hosts File

```bash
adb shell cat /etc/hosts
```

### Verify Network Connectivity from Emulator

```bash
# Ping your host machine from the emulator
adb shell ping 10.0.2.2

# Test DNS resolution inside the emulator
adb shell ping demo.ewqwe.local
```

---

## Transferring Files (CA Certificates, APKs, etc.)

### Push Files to Device

```bash
# Push a CA certificate to Downloads
adb push /path/to/ewqwe-ca.crt /sdcard/Downloads/ewqwe-ca.crt
```

### Push CA Certificate to System Trust Store (Rooted Emulator)

```bash
adb root
adb remount
adb push /path/to/ewqwe-ca.crt /system/etc/security/cacerts/ewqwe-ca.crt
adb reboot
```

### Pull Files from Device

```bash
adb pull /sdcard/Download/some-file.txt /local/path/
```

---

## Viewing Wallet Logs (Logcat)

### Filter by Process ID (EUDI Wallet)

```bash
# Stream logs for the EUDI Wallet process only
adb logcat --pid=$(adb shell pidof eu.europa.ec.euidiw)
```

### Filter by Log Tags

```bash
# Show only specific wallet log tags
adb logcat -s "OpenId4VpManager" "PresentationManager" "WalletCore"
```

> **France Identité**: Substitute the package name or tags used by France Identité.

### Grep for Wallet Keywords

```bash
adb logcat | grep -iE "eudi|openid4vp|presentation|mdoc|wallet"
```

```bash
adb logcat | grep -iE "france|identite|annex_b|dcapi"
```

### Clear Logcat

```bash
adb logcat -c
```

---

## System Information & Debugging

### Check Android Version

```bash
adb shell getprop ro.build.version.release
```

### Check if WebView Supports W3C Digital Credentials

```bash
# Check Chrome version on device
adb shell dumpsys package com.android.chrome | grep versionName
```

### Grant Permissions to a Wallet App

```bash
adb shell pm grant <package_name> android.permission.BLUETOOTH
adb shell pm grant <package_name> android.permission.BLUETOOTH_ADMIN
```

### Open Deep Link / URL Scheme

```bash
# Open an openid4vp deep link on the device
adb shell am start -d "openid4vp://?client_id=..." -a android.intent.action.VIEW

# Open a generic URL
adb shell am start -d "https://example.com" -a android.intent.action.VIEW
```

### Force-Stop and Clear App Data

```bash
adb shell am force-stop <package_name>
adb shell pm clear <package_name>
```

### Reboot the Emulator/Device

```bash
adb reboot
```

---

## Testing Certificates

### Inspect Certificate Chain

```bash
openssl x509 -in your_fullchain.pem -noout -issuer
openssl x509 -in your_cert.pem -noout -subject -issuer
```

### Download Root CA Certificates (e.g., Let's Encrypt)

```bash
curl -s https://letsencrypt.org/certs/isrgrootx1.pem -o isrg_root_x1.pem
curl -s https://letsencrypt.org/certs/isrg-root-x2.pem -o isrg_root_x2.pem
```

---

## Android Emulator-Specific Commands

### Cold Boot

Use when the emulator is unresponsive or has stale state. In Android Studio:
**Device Manager → Right-click device → Cold Boot Now**

### Enable Hardware Keyboard

In Android Studio emulator settings, enable **"Hardware keyboard present"** to use your computer's keyboard.

### Grant Superuser (root)

```bash
adb root
```

> Only works on emulator images or rooted devices. Required for modifying `/etc/hosts` or system-level CA certificates.

### Remount System Partition as Writable

```bash
adb remount
```

> Required after `adb root` to push files to system partitions like `/system/etc/security/cacerts/`.

---

## Quick Reference by Use Case

| What You Need | Command |
|---|---|
| See connected devices | `adb devices` |
| Install an APK | `adb install /path/to/app.apk` |
| Force reinstall | `adb install -r /path/to/app.apk` |
| Check W3C credential providers | `adb shell dumpsys credential` |
| Map demo domain in emulator | `adb root && adb shell "echo '10.0.2.2 demo.ewqwe.local' >> /etc/hosts"` |
| Push CA cert to Downloads | `adb push cert.crt /sdcard/Downloads/` |
| Push CA cert to system store | `adb root && adb remount && adb push cert.crt /system/etc/security/cacerts/` |
| Stream wallet logs | `adb logcat --pid=$(adb shell pidof <package>)` |
| Filter logcat by tags | `adb logcat -s "Tag1" "Tag2"` |
| Search logs for keywords | `adb logcat \| grep -iE "eudi\|openid4vp"` |
| Restart ADB server | `adb kill-server && adb start-server` |
| Check Android version | `adb shell getprop ro.build.version.release` |
| List installed packages | `adb shell pm list packages \| grep -i <keyword>` |
| Open a deep link | `adb shell am start -d "<url>" -a android.intent.action.VIEW` |
| Force-stop an app | `adb shell am force-stop <package>` |
| Clear app data | `adb shell pm clear <package>` |
| Reboot device | `adb reboot` |
| Root the emulator | `adb root` |
| Remount system as writable | `adb remount` |

---

## References

- [Android Developers - ADB Command Reference](https://developer.android.com/tools/adb)
- [Android Developers - Configure On-Device Developer Options](https://developer.android.com/studio/debug/dev-options)
- [Android Developers - Run Apps on a Hardware Device](https://developer.android.com/studio/run/device)
- [Chrome Remote Debugging](https://developer.chrome.com/docs/devtools/remote-debugging/)
