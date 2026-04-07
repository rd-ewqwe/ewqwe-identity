import { WalletApp } from "./wallet.ts";
import { CredentialStore } from "./store.ts";
import { DebugLogger } from "./debug.ts";

// Initialize the wallet application
document.addEventListener("DOMContentLoaded", () => {
  const logger = new DebugLogger("debug-log");
  const store = new CredentialStore(logger);
  const app = new WalletApp(store, logger);
  
  app.initialize();
  
  logger.log("Wallet application initialized");
});
