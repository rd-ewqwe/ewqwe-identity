/**
 * @ewqwe/digital-identity-backend — Transaction Store
 *
 * In-memory storage for OpenID4VP transactions with TTL-based cleanup.
 * Replace with Redis or a database for production use.
 */

import type { OpenID4VPTransaction } from "./types.ts";
import type { TransactionStatus } from "@ewqwe/digital-identity";

export class TransactionStore {
  private store = new Map<string, OpenID4VPTransaction>();
  private cleanupInterval?: ReturnType<typeof setInterval>;

  /**
   * Start periodic cleanup of expired transactions.
   * @param intervalMs How often to run cleanup (default: 60 seconds)
   */
  startCleanup(intervalMs = 60_000): void {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [id, tx] of this.store) {
        if (tx.expiresAt < now) {
          this.store.delete(id);
          console.log(
            `[TransactionStore] Transaction ${id.slice(0, 8)}... expired and removed`,
          );
        }
      }
    }, intervalMs);
  }

  /** Stop the cleanup timer. */
  stopCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = undefined;
    }
  }

  /** Store a new transaction. */
  set(transaction: OpenID4VPTransaction): void {
    this.store.set(transaction.id, transaction);
  }

  /** Retrieve a transaction by ID. Returns undefined if not found. */
  get(id: string): OpenID4VPTransaction | undefined {
    return this.store.get(id);
  }

  /** Find a transaction by its state parameter. */
  findByState(state: string): OpenID4VPTransaction | undefined {
    for (const tx of this.store.values()) {
      if (tx.state === state) return tx;
    }
    return undefined;
  }

  /** Delete a transaction by ID. */
  delete(id: string): boolean {
    return this.store.delete(id);
  }

  /** Update the status of a transaction. */
  updateStatus(id: string, status: TransactionStatus): void {
    const tx = this.store.get(id);
    if (tx) tx.status = status;
  }

  /** Check if a transaction has expired and clean it up. Returns true if expired. */
  isExpired(id: string): boolean {
    const tx = this.store.get(id);
    if (!tx) return true;
    if (tx.expiresAt < Date.now()) {
      this.store.delete(id);
      return true;
    }
    return false;
  }
}
