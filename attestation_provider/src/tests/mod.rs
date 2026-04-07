mod mock_authenticate;

mod test_client;

mod test_logging;
pub use test_logging::log_test;

mod test_server;
pub use test_server::{TestsContext, start_default_test_server};

mod end_to_end_tests;

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
