# EU Age Verification Wallet as a Browser Extension

A browser extension implementing the **Age Verification App Instance (AVI)** from the [EU Age Verification Profile](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile).

## Features

- ✅ Pre-loaded with 6 sample credentials (2 of each type):
  - **Mobile Driver's License (mDL)** - ISO 18013-5
  - **EU Person Identification Data (PID)** - CIR 2024/2977
  - **Proof of Age** - EU Age Verification Profile (`eu.europa.ec.av.1`)
- ✅ W3C Digital Credentials API bridge (in-page request/response)
- ✅ OpenID4VP fallback support (`av://` link interception)
- ✅ `web+av://` protocol handler opens the wallet popup
- ✅ Works on Chrome and Firefox (MV3)

## Installation

### Prerequisites

```bash
# Install dependencies
npm install
```

Requires Node.js 18+.

### Build

```bash
# Build for production
npm run build

# Build with watch mode (development)
npm run build:watch
```

Build output includes bundled scripts and generated icons.

### Load in Chrome

1. Go to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `dist` folder

### Load in Firefox

1. Go to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on...**
3. Select `dist/manifest.json`

### Package for Distribution

```bash
# Chrome zip
npm run package:chrome

# Firefox xpi
npm run package:firefox
```

## Sample Credentials

The wallet comes pre-loaded with:

| Type | DocType | Samples |
|------|---------|---------|
| mDL | `org.iso.18013.5.1.mDL` | 2 (DE, FR) |
| PID | `eu.europa.ec.eudi.pid.1` | 2 (NL, ES) |
| Proof of Age | `eu.europa.ec.av.1` | 2 |

## Architecture

```
wallet-extension/
├── manifest.json          # Extension manifest (MV3)
├── background/
│   └── service-worker.ts  # Message handling, DCQL matching
├── popup/
│   ├── popup.html         # Wallet UI
│   ├── popup.ts           # UI logic
│   └── popup.css          # Styles
├── content/
│   └── content-script.ts  # Page injection for av:// + request bridge
├── build.mjs               # esbuild build script + icon generation
└── src/
  ├── browser.d.ts       # Chrome/Firefox API typings
  ├── types.ts           # Type definitions
  ├── store.ts           # Credential storage (chrome.storage.local)
  └── sample-credentials.ts  # Pre-loaded sample data
```

## EU Age Verification Profile Compliance

This extension implements the AVI requirements from [Annex A](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile):

| Requirement | Status | Notes |
|-------------|--------|-------|
| Custom URL scheme `av://` | 🔶 | Link interception + `web+av://` protocol handler |
| W3C Digital Credentials API | 🔶 | In-page request/response bridge |
| OpenID4VP fallback | 🔶 | DCQL matching only (no crypto) |
| ISO mDoc format | ⏳ | Uses simplified JSON (CBOR pending) |
| P-256/ES256 crypto | ⏳ | Signing not implemented |

## Development

### Project Structure

- **Types**: [src/types.ts](src/types.ts) - All TypeScript interfaces
- **Storage**: [src/store.ts](src/store.ts) - `CredentialStore` class using `chrome.storage.local`
- **Sample Data**: [src/sample-credentials.ts](src/sample-credentials.ts) - Pre-loaded credentials
- **Background**: [background/service-worker.ts](background/service-worker.ts) - Message handling
- **Popup**: [popup/popup.ts](popup/popup.ts) - Wallet UI controller
- **Content Script**: [content/content-script.ts](content/content-script.ts) - Page integration

### Protocol Handling

- `web+av://` is registered in the extension manifest and opens the popup.
- `av://` links are intercepted in-page by the content script for OpenID4VP fallback.

Example format handled by the popup:

- `web+av://request?type=proof-of-age&claims=age_over_18,age_over_21&return=https%3A%2F%2Fexample.com`

### In-Page Request Bridge

Pages can send a request event and receive a response via `window.postMessage`.
The content script listens for `EU_AV_WALLET_REQUEST` and responds with `EU_AV_WALLET_RESPONSE`.

### Adding More Credentials

Edit [src/sample-credentials.ts](src/sample-credentials.ts) to add new sample credentials.

## Future Work

- [ ] OpenID4VCI issuance flow (Rust AP in development)
- [ ] CBOR/mDoc encoding/decoding
- [ ] HPKE encryption for DC API responses
- [ ] Zero-Knowledge Proofs (optional per EU AV profile)
- [ ] Device signature generation

## References

- [EU Age Verification Profile](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile).
- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/).
- [ISO 18013-5 (mDL)](https://www.iso.org/standard/69084.html).
- [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

## License

See project root LICENSE file.
