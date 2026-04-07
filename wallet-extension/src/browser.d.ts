/**
 * Browser Extension API Type Declarations
 *
 * Provides type definitions for cross-browser extension APIs.
 * Firefox uses `browser.*` while Chrome uses `chrome.*`.
 */

// Declare the Firefox browser global
declare const browser: typeof chrome | undefined;

// Extend chrome types for missing properties
declare namespace chrome.runtime {
  interface InstalledDetails {
    reason: "install" | "update" | "chrome_update" | "shared_module_update";
    previousVersion?: string;
    id?: string;
  }
}
