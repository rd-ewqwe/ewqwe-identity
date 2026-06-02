# EUDI Wallet W3C Digital Credentials API Analysis

> How the EUDI Android Wallet (`eudi-app-android-wallet-ui`) implements Annex C Sub-protocol B and what this means for the ewqwe-identity webapp.

## Executive Summary

The EUDI Wallet implements Annex C Sub-protocol B (OpenID4VP over W3C Digital Credentials API) using an **Activity intent filter** approach rather than the standard `CredentialProviderService`. This analysis reveals that this approach **does not work with Chrome on Android 14+**, because Chrome delegates to Android's CredentialManager, which only dispatches to `CredentialProviderService` implementations — not to activities with intent filters.

**Bottom line**: The installed EUDI Wallet version on your device (`yyyy.mm.v`) cannot receive Annex C Sub-protocol B requests from Chrome. Use Annex B (cross-device QR / same-device deep link) as a working alternative.

---

## 1. How the EUDI Wallet Registers for DC API

### AndroidManifest Registration (Source Code)

**File**: `assembly-logic/src/main/AndroidManifest.xml`

```xml
<intent-filter> <!-- Required for DCAPI -->
    <action android:name="androidx.credentials.registry.provider.action.GET_CREDENTIAL" />
    <action android:name="androidx.identitycredentials.action.GET_CREDENTIALS" />
    <category android:name="android.intent.category.DEFAULT" />
</intent-filter>
```

This is declared on the `MainActivity`, NOT as a `CredentialProviderService`. Verified on the device:

```
$ adb shell dumpsys package eu.europa.ec.euidi | grep -A5 "GET_CREDENTIAL"
Non-Data Actions:
    androidx.credentials.registry.provider.action.GET_CREDENTIAL:
        MainActivity filter bc813c2
        Action: "androidx.credentials.registry.provider.action.GET_CREDENTIAL"
        Action: "androidx.identitycredentials.action.GET_CREDENTIALS"
        Category: "android.intent.category.DEFAULT"
```

### What is NOT Registered

There is **no** `CredentialProviderService` in the EUDI wallet. Verified via:

1. **Source code check**: No `CredentialProviderService` anywhere in the source tree
2. **Merged manifest check**: No `CredentialProviderService` in the build output
3. **SDK AAR check**: `eudi-lib-android-wallet-core-0.28.1.aar` has an empty manifest
4. **Device check**: `adb shell dumpsys credential` returns empty
5. **Provider check**: `adb shell cmd package resolve-activity -a "androidx.credentials.registry.provider.action.GET_CREDENTIAL"` resolves only `ResolverActivity` (the Android system dialog), NOT the EUDI wallet

### How CredentialManager Works on Android 14+

Android 14+ introduced `CredentialManager` as the system service for managing credentials (passkeys, passwords, digital credentials). When Chrome calls `navigator.credentials.get({ digital: ... })`:

```
Chrome
  ↓  calls CredentialManager API
android.security.identity.CredentialManager
  ↓  looks for registered providers
dumpsys credential → checks CredentialProviderService list
  ↓  dispatches to provider
bindService() → CredentialProviderService.onGetCredential()
```

CredentialManager dispatches to providers via `bindService()`, which requires a proper `<service>` declaration with `android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE`. An `<intent-filter>` on an `<activity>` is invisible to CredentialManager.

### Why This Matters

| Registration Type | Visible in `dumpsys credential`? | Receives DC API from Chrome? |
|---|---|---|
| `CredentialProviderService` (service) | ✅ Yes | ✅ Yes |
| Intent filter on Activity (current EUDI approach) | ❌ No | ❌ No |

---

## 2. The SDK Method: `startDCAPIPresentation()`

The EUDI wallet SDK does have a method `eudiWallet.startDCAPIPresentation(Intent)` (from `eudi-lib-android-wallet-core:0.28.1`):

```kotlin
// In WalletCorePresentationController.kt
private fun addListener(listener: TransferEvent.Listener) {
    when (safeConfig) {
        is PresentationControllerConfig.DcApi -> {
            eudiWallet.startDCAPIPresentation(safeConfig.startIntent)
        }
    }
}
```

This method processes an Android Intent (received via CredentialManager) and:
1. Extracts the OpenID4VP Authorization Request from the Intent's extras
2. Processes DCQL queries
3. Finds matching documents in the wallet
4. Fires transfer events (`RequestReceived`, `ResponseSent`, etc.)
5. Returns the response through CredentialManager

But this method can only fire if the Intent is **received** — and without a `CredentialProviderService`, the Intent is never dispatched.

---

## 3. The Credential Registry Library (Alternative Path)

The EUDI wallet depends on:

```kotlin
// From EudiWalletCorePlugin.kt
implementation("androidx.credentials.registry:registry-provider-play-services:1.0.0-alpha04")
```

This library provides a `RegistryManagerProviderMetadataHolder` service that references `RegistryManagerProviderPlayServicesImpl`. This is a **Play Services-based credential registry** — a different system from CredentialManager. It may work independently but:

- It's still in **alpha** (1.0.0-alpha04)
- It requires Google Play Services to be properly configured
- It does NOT register as a `CredentialProviderService`
- It does NOT appear in `dumpsys credential`

---

## 4. What Happens on Your Device

```
Webapp calls navigator.credentials.get({ digital: { protocol: "openid4vp-v1-unsigned" }})
  ↓
Chrome 148 → delegates to Android CredentialManager
  ↓
CredentialManager checks registered CredentialProviderService providers
  ↓
dumpsys credential → EMPTY (no provider registered)
  ↓
No handler found → error returned
  ↓
"Request was cancelled or no credentials found" / "Your info was not found"
```

Verified facts:

| Check | Result |
|---|---|
| `adb -d shell dumpsys credential` | Empty |
| Wallet intent filter present? | ✅ Yes (in manifest) |
| `CredentialProviderService` registered? | ❌ No |
| Intent received by wallet? (logcat) | ❌ No |
| Chrome version | 148.0.7778.215 |
| Android version | 16 (SDK 36) |

---

## 5. Webapp Side: Nothing to Change

The webapp's `requestViaOpenID4VPOverDCAPI()` implementation is **correct**:

```typescript
const credential = await navigator.credentials.get({
    digital: {
      requests: [
        {
          protocol: "openid4vp-v1-unsigned",
          data: openid4vpRequest,
        },
      ],
    },
  } as CredentialRequestOptions);
```

The issue is not in the request format, the protocol identifier, or the response handling. The `navigator.credentials.get()` call correctly delegates to Chrome → CredentialManager. The problem is that **no credential provider exists on the device to handle the request**.

---

## 6. Complete EUDI Wallet Data Flow (For Reference)

This is the flow as designed in the EUDI wallet source code (if a proper `CredentialProviderService` were registered):

```
1. MANIFEST: MainActivity intent filter for GET_CREDENTIAL action
       ↓
2. EudiComponentActivity.handleDeepLink(intent)
   → hasIntentAction(intent) → IntentType.DC_API
       ↓
3. Cache intent, navigate to Dashboard
       ↓
4. DashboardViewModel.handleDeepLink()
   → Creates RequestUriConfig(PresentationMode.DcApi(...))
   → Emits Navigation.OpenIntentAction(intentAction, arguments)
       ↓
5. IntentActionHelper.handleIntentAction()
   → Navigates to PresentationScreens.PresentationRequest
   → Stores IntentAction in back stack savedStateHandle
       ↓
6. PresentationRequestViewModel.init()
   → interactor.setConfig(requestUriConfig, intentAction)
       ↓
7. PresentationRequestInteractorImpl.setConfig()
   → walletCorePresentationController.setConfig(
        PresentationControllerConfig.DcApi(initiator, startIntent)
      )
       ↓
8. WalletCorePresentationController.addListener()
   → eudiWallet.startDCAPIPresentation(startIntent)  // SDK v0.28.1
       ↓
9. SDK processes Intent extras → extracts OpenID4VP request
   → matches DCQL against stored documents
   → fires TransferEvent.RequestReceived
       ↓
10. User approves → SDK builds VP token
    → eudiWallet.sendResponse(response)
    → fires TransferEvent.ResponseSent / IntentToSend
       ↓
11. Response returned to CredentialManager → back to Chrome → back to webapp
```

**Key files** in the EUDI wallet codebase:

| Purpose | File |
|---------|------|
| Intent filter | `assembly-logic/src/main/AndroidManifest.xml` |
| Intent receipt | `ui-logic/src/main/java/eu/europa/ec/uilogic/container/EudiComponentActivity.kt` |
| Intent type enum | `ui-logic/src/main/java/eu/europa/ec/uilogic/navigation/helper/IntentAction.kt` |
| Intent classification | `ui-logic/src/main/java/eu/europa/ec/uilogic/navigation/helper/IntentActionHelper.kt` |
| Dashboard dispatch | `dashboard-feature/src/main/java/eu/europa/ec/dashboardfeature/ui/dashboard/DashboardViewModel.kt` |
| Presentation mode config | `common-feature/src/main/java/eu/europa/ec/commonfeature/config/RequestUriConfig.kt` |
| Presentation request viewmodel | `presentation-feature/src/main/java/eu/europa/ec/presentationfeature/ui/request/PresentationRequestViewModel.kt` |
| Presentation interactor | `presentation-feature/src/main/java/eu/europa/ec/presentationfeature/interactor/PresentationRequestInteractor.kt` |
| Core controller (SDK bridge) | `core-logic/src/main/java/eu/europa/ec/corelogic/controller/WalletCorePresentationController.kt` |
| SDK dependency | `eudi-lib-android-wallet-core:0.28.1` (external) |

---

## 7. Recommendations

### For Testing Now — Use Annex B (Works)

Both the EUDI Wallet and France Identité properly register for OpenID4VP deep link schemes:

```
openid4vp://
mdoc-openid4vp://
eudi-openid4vp://
av://
```

Use the RP's working Annex B flows:
- **Cross-device** (`openid4vp-cross-device`): QR code scanning
- **Same-device** (`openid4vp-same-device`): Deep link redirect
- **Fallback** (`w3c-dc-fallback`): Tries Sub-protocol B → A → cross-device (cross-device will work)

### For Sub-protocol B to Work — Need a CredentialProviderService

The EUDI wallet needs to add a proper `CredentialProviderService` declaration:

```xml
<service
    android:name=".DcApiCredentialProviderService"
    android:exported="true"
    android:permission="android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE">
    <intent-filter>
        <action android:name="android.service.credentials.CredentialProviderService" />
    </intent-filter>
</service>
```

This is a wallet-side change, not something the webapp can fix.

### For a Webapp-Only Path — PostMessage Bridge

The wallet extension (`wallet-extension/`) uses a custom `postMessage`-based protocol but the webapp doesn't use it for Sub-protocol B. To make it work:

- The webapp would need to use `window.postMessage()` instead of (or as a fallback from) `navigator.credentials.get()`
- The wallet extension's content script already handles `EU_AV_WALLET_REQUEST` messages

This is a significant architectural change and is not recommended as a primary approach.
