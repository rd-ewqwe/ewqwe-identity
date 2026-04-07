import { RelyingPartyApp } from "./rp.ts";
import { DebugLogger } from "./debug.ts";

// Initialize the relying party application
document.addEventListener("DOMContentLoaded", () => {
  const logger = new DebugLogger();
  const app = new RelyingPartyApp(logger);
  
  app.initialize();
  
  logger.log("Relying Party application initialized");
});
