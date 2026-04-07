/**
 * EU Age Verification Wallet - Storage Adapter
 *
 * Handles credential storage using browser extension storage API.
 * Compatible with Chrome (chrome.storage) and Firefox (browser.storage).
 */

import type { StoredCredential, CredentialType } from "./types";
import { generateSampleCredentials } from "./sample-credentials";

// Cross-browser storage API
const storage =
  typeof browser !== "undefined" ? browser.storage : chrome.storage;

const STORAGE_KEY = "wallet_credentials";
const INITIALIZED_KEY = "wallet_initialized";

/**
 * Credential Store for browser extension
 */
export class CredentialStore {
  private credentials: Map<string, StoredCredential> = new Map();
  private initialized = false;

  /**
   * Initialize the store - loads from storage or initializes with samples
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      const result = await storage.local.get([STORAGE_KEY, INITIALIZED_KEY]);

      if (result[INITIALIZED_KEY]) {
        // Load existing credentials
        const stored = result[STORAGE_KEY] as StoredCredential[] | undefined;
        if (stored) {
          stored.forEach((cred) => this.credentials.set(cred.id, cred));
        }
      } else {
        // First run - load sample credentials
        await this.loadSampleCredentials();
        await storage.local.set({ [INITIALIZED_KEY]: true });
      }

      this.initialized = true;
      console.log(
        `[Wallet] Initialized with ${this.credentials.size} credentials`,
      );
    } catch (error) {
      console.error("[Wallet] Failed to initialize storage:", error);
      throw error;
    }
  }

  /**
   * Load sample credentials for demo purposes
   */
  private async loadSampleCredentials(): Promise<void> {
    const samples = generateSampleCredentials();
    samples.forEach((cred) => this.credentials.set(cred.id, cred));
    await this.persist();
    console.log(`[Wallet] Loaded ${samples.length} sample credentials`);
  }

  /**
   * Reset wallet to sample credentials
   */
  async reset(): Promise<void> {
    this.credentials.clear();
    await this.loadSampleCredentials();
  }

  /**
   * Persist credentials to storage
   */
  private async persist(): Promise<void> {
    const credentials = Array.from(this.credentials.values());
    await storage.local.set({ [STORAGE_KEY]: credentials });
  }

  /**
   * Get all credentials
   */
  getAll(): StoredCredential[] {
    return Array.from(this.credentials.values());
  }

  /**
   * Get credential by ID
   */
  get(id: string): StoredCredential | undefined {
    return this.credentials.get(id);
  }

  /**
   * Get credentials by type
   */
  getByType(type: CredentialType): StoredCredential[] {
    return this.getAll().filter((cred) => cred.type === type);
  }

  /**
   * Get credentials by docType (ISO/EU identifier)
   */
  getByDocType(docType: string): StoredCredential[] {
    return this.getAll().filter((cred) => cred.docType === docType);
  }

  /**
   * Find credentials matching a DCQL query
   */
  findMatchingCredentials(
    docType: string,
    requestedClaims: string[],
  ): StoredCredential[] {
    return this.getByDocType(docType).filter((cred) => {
      // Check if credential has all requested claims
      return requestedClaims.every((claim) => claim in cred.claims);
    });
  }

  /**
   * Add a new credential
   */
  async add(credential: StoredCredential): Promise<void> {
    this.credentials.set(credential.id, credential);
    await this.persist();
  }

  /**
   * Remove a credential
   */
  async remove(id: string): Promise<boolean> {
    const deleted = this.credentials.delete(id);
    if (deleted) {
      await this.persist();
    }
    return deleted;
  }

  /**
   * Check if a credential is expired
   */
  isExpired(credential: StoredCredential): boolean {
    const expiryDate = new Date(credential.expiresAt);
    return expiryDate < new Date();
  }

  /**
   * Get valid (non-expired) credentials
   */
  getValidCredentials(): StoredCredential[] {
    return this.getAll().filter((cred) => !this.isExpired(cred));
  }

  /**
   * Get credential count by type
   */
  getCountByType(): Record<CredentialType, number> {
    const counts: Record<CredentialType, number> = {
      mdl: 0,
      "national-id": 0,
      "proof-of-age": 0,
    };

    this.getAll().forEach((cred) => {
      if (cred.type in counts) {
        counts[cred.type]++;
      }
    });

    return counts;
  }
}

// Singleton instance
let storeInstance: CredentialStore | null = null;

export async function getCredentialStore(): Promise<CredentialStore> {
  if (!storeInstance) {
    storeInstance = new CredentialStore();
    await storeInstance.initialize();
  }
  return storeInstance;
}
