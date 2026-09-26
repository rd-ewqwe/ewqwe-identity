# ADB troubleshooting reference for wallet testing

A reference of `adb` commands used when testing digital wallets (EUDI Wallet, France Identité, and others) with the ewQwe Credential Verifier.

> [!NOTE]
> `adb` is typically located at `~/Library/Android/sdk/platform-tools/adb` on macOS when installed through Android Studio. Add it to your `PATH` for convenience.

---

## Device and connection management

### List connected devices

```bash
# List all connected devices and emulators
adb devices

# List only emulator devices
adb devices -e

# List only physical (USB) devices
adb devices -d
```

### Restart the ADB server

```bash
adb kill-server
adb start-server
```

Use this when `adb devices` shows no devices even though an emulator is running or a device is connected through USB.

### Connect to a specific device

```bash
# Use -s with the device serial for single-target commands
adb -s <device_serial> install app.apk

# Use -e for an emulator
adb -e install app.apk

# Use -d for a physical device (USB)
adb -d install app.apk
```

---

## Install and manage APKs

### Install an APK

```bash
# Basic install
adb install /path/to/your-app.apk

# Reinstall (overwrite the existing app, keep the data)
adb install -r /path/to/your-app.apk

# Install to an emulator
adb -e install /path/to/your-app.apk

# Install to a specific device
adb -s <device_serial> install /path/to/your-app.apk
```

### Uninstall an app

```bash
adb uninstall <package_name>

# Example: EUDI Wallet
adb uninstall eu.europa.ec.euidiw

# Example: France Identité
adb uninstall fr.gouv.interieur.franceidentite
```

### List installed packages

```bash
# List all packages
adb shell pm list packages

# Filter by keyword
adb shell pm list packages | grep -i eudi
adb shell pm list packages | grep -i france
adb shell pm list packages | grep -i identite
```

---

## W3C Digital Credentials API provider registration

### Check registered credential providers

```bash
# List all credential providers registered with Android CredentialManager
adb shell dumpsys credential
```

Interpretation:

- **Empty or missing output**: no wallet has registered as a `CredentialProviderService` with the Android CredentialManager on this device.
- **Populated output**: the wallets that implement a `CredentialProviderService` appear here. Look for entries under `credential-services`.

> [!IMPORTANT]
> Some wallets, including the EUDI Wallet, implement Annex C Sub-protocol B with an **Activity intent filter** on their MainActivity, for the actions `androidx.credentials.registry.provider.action.GET_CREDENTIAL` and `androidx.identitycredentials.action.GET_CREDENTIALS`, **instead of** a `CredentialProviderService`. This approach does not appear in `dumpsys credential`.
>
> This Activity-based approach **does not work** with Chrome on Android 14 and later. Chrome delegates to the Android CredentialManager, which dispatches only to `CredentialProviderService` implementations, and never to Activities with intent filters. The Digital Credentials API request never reaches the wallet.

---

## DNS and network configuration

### Map demo.ewqwe.local to the host machine (emulator)

For the Android emulator, the host machine is reachable at `10.0.2.2`. Map the demo domain inside the emulator:

```bash
adb root && adb shell "echo '10.0.2.2  demo.ewqwe.local' >> /etc/hosts"
```

> [!WARNING]
> This command requires `adb root`, which works only on an emulator or a rooted device. Start the emulator with `-writable-system`.

### Verify the hosts file

```bash
adb shell cat /etc/hosts
```

### Verify network connectivity from the emulator

```bash
# Ping the host machine from the emulator
adb shell ping 10.0.2.2

# Test DNS resolution inside the emulator
adb shell ping demo.ewqwe.local
```

---

## Transfer files (CA certificates, APKs, and others)

### Push files to the device

```bash
# Push a CA certificate to Downloads
adb push /path/to/ewqwe-ca.crt /sdcard/Downloads/ewqwe-ca.crt
```

### Push a CA certificate to the system trust store (rooted emulator)

```bash
adb root
adb remount
adb push /path/to/ewqwe-ca.crt /system/etc/security/cacerts/ewqwe-ca.crt
adb reboot
```

### Pull files from the device

```bash
adb pull /sdcard/Download/some-file.txt /local/path/
```

---

## View wallet logs (logcat)

### Filter by process ID (EUDI Wallet)

```bash
# Stream logs for the EUDI Wallet process only
adb logcat --pid=$(adb shell pidof eu.europa.ec.euidiw)
```

### Filter by log tags

```bash
# Show only specific wallet log tags
adb logcat -s "OpenId4VpManager" "PresentationManager" "WalletCore"
```

> [!NOTE]
> For France Identité, substitute the package name or the tags that France Identité uses.

### Search the logs for wallet keywords

```bash
adb logcat | grep -iE "eudi|openid4vp|presentation|mdoc|wallet"
```

```bash
adb logcat | grep -iE "france|identite|annex_b|dcapi"
```

### Clear logcat

```bash
adb logcat -c
```

---

## System information and debugging

### Check the Android version

```bash
adb shell getprop ro.build.version.release
```

### Check whether WebView supports W3C Digital Credentials

```bash
# Check the Chrome version on the device
adb shell dumpsys package com.android.chrome | grep versionName
```

### Grant permissions to a wallet app

```bash
adb shell pm grant <package_name> android.permission.BLUETOOTH
adb shell pm grant <package_name> android.permission.BLUETOOTH_ADMIN
```

### Open a deep link or URL scheme

```bash
# Open an openid4vp deep link on the device
adb shell am start -d "openid4vp://?client_id=..." -a android.intent.action.VIEW

# Open a generic URL
adb shell am start -d "https://example.com" -a android.intent.action.VIEW
```

### Force-stop an app and clear its data

```bash
adb shell am force-stop <package_name>
adb shell pm clear <package_name>
```

### Reboot the emulator or device

```bash
adb reboot
```

---

## Test certificates

### Inspect a certificate chain

```bash
openssl x509 -in your_fullchain.pem -noout -issuer
openssl x509 -in your_cert.pem -noout -subject -issuer
```

### Download root CA certificates (for example, Let's Encrypt)

```bash
curl -s https://letsencrypt.org/certs/isrgrootx1.pem -o isrg_root_x1.pem
curl -s https://letsencrypt.org/certs/isrg-root-x2.pem -o isrg_root_x2.pem
```

---

## Android emulator commands

### Cold boot

Use this when the emulator is unresponsive or has stale state. In Android Studio, open **Device Manager**, right-click the device, and select **Cold Boot Now**.

### Enable the hardware keyboard

In the Android Studio emulator settings, enable **"Hardware keyboard present"** to use the keyboard of your computer.

### Grant superuser (root)

```bash
adb root
```

> [!NOTE]
> This works only on emulator images or rooted devices. It is required to modify `/etc/hosts` or the system-level CA certificates.

### Remount the system partition as writable

```bash
adb remount
```

> [!NOTE]
> This is required after `adb root` to push files to system partitions such as `/system/etc/security/cacerts/`.

---

## Quick reference by use case

| What you need                  | Command                                                                      |
| :----------------------------- | :--------------------------------------------------------------------------- |
| See connected devices          | `adb devices`                                                                |
| Install an APK                 | `adb install /path/to/app.apk`                                               |
| Force reinstall                | `adb install -r /path/to/app.apk`                                            |
| Check W3C credential providers | `adb shell dumpsys credential`                                               |
| Map demo domain in emulator    | `adb root && adb shell "echo '10.0.2.2 demo.ewqwe.local' >> /etc/hosts"`     |
| Push CA cert to Downloads      | `adb push cert.crt /sdcard/Downloads/`                                       |
| Push CA cert to system store   | `adb root && adb remount && adb push cert.crt /system/etc/security/cacerts/` |
| Stream wallet logs             | `adb logcat --pid=$(adb shell pidof <package>)`                              |
| Filter logcat by tags          | `adb logcat -s "Tag1" "Tag2"`                                                |
| Search logs for keywords       | `adb logcat \| grep -iE "eudi\|openid4vp"`                                   |
| Restart ADB server             | `adb kill-server && adb start-server`                                        |
| Check Android version          | `adb shell getprop ro.build.version.release`                                 |
| List installed packages        | `adb shell pm list packages \| grep -i <keyword>`                            |
| Open a deep link               | `adb shell am start -d "<url>" -a android.intent.action.VIEW`                |
| Force-stop an app              | `adb shell am force-stop <package>`                                          |
| Clear app data                 | `adb shell pm clear <package>`                                               |
| Reboot device                  | `adb reboot`                                                                 |
| Root the emulator              | `adb root`                                                                   |
| Remount system as writable     | `adb remount`                                                                |

---

## References

- [Android Developers - ADB Command Reference](https://developer.android.com/tools/adb)
- [Android Developers - Configure On-Device Developer Options](https://developer.android.com/studio/debug/dev-options)
- [Android Developers - Run Apps on a Hardware Device](https://developer.android.com/studio/run/device)
- [Chrome Remote Debugging](https://developer.chrome.com/docs/devtools/remote-debugging/)
