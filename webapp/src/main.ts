import { RelyingPartyApp } from "./relying_party_app.ts";
import { DebugLogger } from "./debug.ts";

// Initialize the relying party application
document.addEventListener("DOMContentLoaded", () => {
  const logger = new DebugLogger();
  const app = new RelyingPartyApp(logger);

  app.initialize();

  logger.log("Relying Party application initialized");
});
