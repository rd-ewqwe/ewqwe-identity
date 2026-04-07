//! Store implementations for the Verifier App.

mod postgres;
mod sqlite;

pub use postgres::PostgresVerifierAppStore;
pub use sqlite::SqliteVerifierAppStore;
