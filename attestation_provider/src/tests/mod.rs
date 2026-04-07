#![allow(unused_imports)]

mod context;
pub use context::TestsContext;

mod logging;
pub use logging::log_test;

mod test_client;
pub use test_client::TestClient;

mod test_server;
pub use test_server::{start_default_test_server, start_test_server};

use std::sync::Once;

/// Initialize tracing/logging once for the entire test process.
/// Prevents panics like: "Tracing already initialized or crashed" when tests
/// or multiple crates call `tracing::log_init` concurrently.
static INIT_LOGGING: Once = Once::new();

pub fn init_test_logging(rust_log: Option<&str>) {
    INIT_LOGGING.call_once(|| {
        ewqwe_logging::log_init(rust_log.or(option_env!("RUST_LOG")));
    });
}
