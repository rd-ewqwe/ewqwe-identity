# Install the demo wallet extension

This tutorial builds and loads the demo wallet extension in Chrome. At the end, the wallet holds six sample credentials.

A wallet extension is a browser add-on that stores credentials and presents them to a web application on request.

## What you need

- Node.js 18 or later.
- Google Chrome or a Chromium-based browser.
- The repository on your computer.

## Steps

### 1. Build the extension

```bash
cd wallet-extension
npm install
npm run build
```

Expected: the build prints the output directory and the steps to load the extension. The output directory is `wallet-extension/dist`. It contains `manifest.json`, `background/`, `popup/`, `content/`, and `icons/`.

The build script runs esbuild. It bundles the background service worker, the popup script, and the content script, and it generates the toolbar icons.

### 2. Load the extension in Chrome

1. Open `chrome://extensions/`.
2. Turn on **Developer mode**.
3. Click **Load unpacked**.
4. Select the `wallet-extension/dist` directory.

Expected: the extensions page shows **EU Age Verification Wallet**, version 0.1.0.

### 3. Open the wallet

Click the extension icon in the toolbar.

Expected: the popup opens with the title **EU AV Wallet**. The summary shows three counts: **mDL 2**, **PID 2**, and **Proof of Age 2**. The list below shows the six credentials.

The extension stored the sample credentials in the browser. The list is the current wallet content.

### 4. Inspect a credential

Click a credential card.

Expected: a detail modal shows the credential type, the document type, and the claims of the credential. For example, a Proof of Age credential shows `age_over_18`.

Click **Close** to close the modal.

### 5. Restore the sample credentials

Click **Reset** and confirm.

Expected: the wallet reloads the six sample credentials and the summary returns to the original counts.

> [!WARNING]
> The demo wallet is not an EU-certified wallet. It stores the credentials without encryption, and the credentials are not signed by a trusted issuer. Use the demo wallet only for demonstration and testing.

## Troubleshooting

| Symptom                       | Cause                                 | Action                                                |
| :---------------------------- | :------------------------------------ | :---------------------------------------------------- |
| `npm run build` fails         | Node.js is missing, or older than 18. | Install Node.js 18 or later.                          |
| The extension does not appear | The wrong directory was selected.     | Load `wallet-extension/dist`, not `wallet-extension`. |
| The wallet is empty           | The sample data was removed.          | Click **Load sample credentials**.                    |

## Next steps

- [Present a stored credential](./present-a-stored-credential.md)
- [Credential types](../../reference/digital-credential/credential-types.md)
