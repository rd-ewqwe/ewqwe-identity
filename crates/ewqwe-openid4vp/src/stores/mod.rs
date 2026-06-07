//! Concrete transaction-store implementations.
//!
//! Each sub-module provides a backend for the [`crate::transaction::TransactionStore`] trait:
//!
//! | Module       | Backend                                             |
//! |--------------|-----------------------------------------------------|
//! | `memory`     | In-process `HashMap` (default, no persistence)     |
//! | `sqlite`     | SQLite in-memory or file via `sqlx`                 |

pub mod memory;
pub mod sqlite;

pub use memory::InMemoryTransactionStore;
pub use sqlite::SqliteTransactionStore;
