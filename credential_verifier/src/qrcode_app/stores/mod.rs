//! Store implementations for the QR Code APP.

mod sqlite;
mod postgres;

pub use sqlite::SqliteQrcodeAppStore;
pub use postgres::PostgresQrcodeAppStore;
