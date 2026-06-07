//! # ewqwe_logging
//!
//! A lightweight logging library providing stdout-based tracing with flexible
//! configuration and environment-based filtering.
//!
//! ## Features
//!
//! - **Stdout Logging**: Configurable console output with optional ANSI colors
//! - **Environment Filtering**: Set log levels via `RUST_LOG` or config
//! - **Guard Pattern**: RAII guard ensures proper cleanup
//!
//! ## Quick Start
//!
//! ```
//! use ewqwe_logging::log_init;
//!
//! // Initialize with debug level logging
//! log_init(Some("debug"));
//!
//! tracing::info!("Application started");
//! tracing::debug!("Debug information");
//! ```
//!
//! ### Custom Configuration
//!
//! ```no_run
//! use ewqwe_logging::{TracingConfig, tracing_init};
//!
//! let config = TracingConfig {
//!     rust_log: Some("info".to_string()),
//!     with_ansi_colors: true,
//! };
//!
//! // Keep the guard alive for the application lifetime
//! let _guard = tracing_init(&config);
//!
//! tracing::info!("Service initialized");
//! ```
//!
//! ## Configuration
//!
//! The library provides a single configuration structure:
//!
//! - [`TracingConfig`]: Controls log level filtering and ANSI color output
//!
//! ## Important Notes
//!
//! ### Guard Lifetime
//!
//! The `LoggingGuards` returned by [`tracing_init`] must be kept alive for the entire
//! application lifetime to ensure proper cleanup.

mod error;
pub use error::LoggerError;

mod tracing_bridge;
pub use tracing_bridge::{tracing_init, LoggingGuards, TracingConfig};

/// Initialize stdout-only logging.
///
/// This is a simplified initialization function for applications that only need
/// console output. It's particularly useful for development, testing, and
/// simple CLI tools.
///
/// # Arguments
///
/// * `rust_log` - Optional log filter string. If `None`, uses the `RUST_LOG`
///   environment variable.
///
/// # Examples
///
/// ```
/// use ewqwe_logging::log_init;
///
/// // Initialize with debug level
/// log_init(Some("debug"));
/// tracing::info!("This is an info message");
/// tracing::debug!("This is a debug message");
/// ```
///
/// ```
/// use ewqwe_logging::log_init;
///
/// // Use RUST_LOG environment variable
/// log_init(None);
/// ```
///
/// # Notes
///
/// - Calling `log_init(None)` is equivalent to
///   `log_init(option_env!("RUST_LOG"))`
/// - ANSI colors are disabled by default
/// - Logs only to stdout
///
/// # Panics
///
/// Does not panic. If initialization fails, an error message is printed to
/// stderr and the function returns with minimal logging capability.
pub fn log_init(rust_log: Option<&str>) {
    let config = TracingConfig {
        rust_log: rust_log
            .or(option_env!("RUST_LOG"))
            .map(std::borrow::ToOwned::to_owned),
        with_ansi_colors: false,
    };
    tracing_init(&config);
}
