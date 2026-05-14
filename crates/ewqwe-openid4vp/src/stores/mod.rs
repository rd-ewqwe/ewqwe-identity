//! Concrete transaction-store implementations.
//!
//! Each sub-module provides a backend for the [`crate::transaction::TransactionStore`] trait:
//!
//! | Module       | Backend                                             |
//! |--------------|-----------------------------------------------------|
//! | `memory`     | In-process `HashMap` (default, no persistence)     |
//! | `sqlite`     | SQLite in-memory or file via `sqlx`                 |
//! | `postgres`   | PostgreSQL via `sqlx`                               |
//! | `redis`      | Redis with TTL-native expiry (no cleanup thread)    |

pub mod memory;
pub mod postgres;
pub mod redis;
pub mod sqlite;

pub use memory::InMemoryTransactionStore;
pub use postgres::PostgresTransactionStore;
pub use redis::RedisTransactionStore;
pub use sqlite::SqliteTransactionStore;
