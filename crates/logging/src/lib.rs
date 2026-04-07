//! # ewqwe_logging
//!
//! A comprehensive and flexible logging library providing unified telemetry with support for
//! multiple backends including stdout, file logging, syslog (Unix), and OpenTelemetry Protocol (OTLP).
//!
//! ## Features
//!
//! - **Multiple Logging Backends**: stdout, daily rolling files, syslog, and OTLP
//! - **OpenTelemetry Integration**: Distributed tracing and metrics collection
//! - **Flexible Configuration**: Environment-based filtering and fine-grained control
//! - **Production-Ready**: Automatic cleanup, graceful error handling, non-blocking I/O
//!
//! ## Quick Start
//!
//! ### Simple Console Logging
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
//! ### Full Telemetry Setup
//!
//! ```no_run
//! use ewqwe_logging::{TracingConfig, TelemetryConfig, tracing_init};
//!
//! let config = TracingConfig {
//!     service_name: "my-service".to_string(),
//!     otlp: Some(TelemetryConfig {
//!         version: Some("1.0.0".to_string()),
//!         environment: Some("production".to_string()),
//!         otlp_url: "http://localhost:4317".to_string(),
//!         enable_metering: true,
//!     }),
//!     no_log_to_stdout: false,
//!     #[cfg(not(target_os = "windows"))]
//!     log_to_syslog: false,
//!     log_to_file: Some((
//!         std::path::PathBuf::from("./logs"),
//!         "my-service".to_string()
//!     )),
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
//! The library provides two main configuration structures:
//!
//! - [`TracingConfig`]: Main configuration for the logging system
//! - [`TelemetryConfig`]: OpenTelemetry-specific configuration
//!
//! See the [README](https://github.com/your-repo/ewqwe-auth/tree/main/crates/logging) for
//! detailed configuration options and examples.
//!
//! ## Important Notes
//!
//! ### Tokio Test Compatibility
//!
//! Use [`log_init`] instead of [`tracing_init`] in `#[tokio::test]` functions due to
//! OTLP gRPC provider limitations.
//!
//! ### Guard Lifetime
//!
//! The `LoggingGuards` returned by [`tracing_init`] must be kept alive for the entire
//! application lifetime to ensure proper cleanup of telemetry providers.

mod error;
pub use error::LoggerError;

mod otlp;

mod tracing_bridge;
pub use tracing_bridge::{LoggingGuards, TelemetryConfig, TracingConfig, tracing_init};

/// Initialize stdout-only logging (no OpenTelemetry or syslog).
///
/// This is a simplified initialization function for applications that only need console output.
/// It's particularly useful for development, testing, and simple CLI tools.
///
/// # Arguments
///
/// * `rust_log` - Optional log filter string. If `None`, uses the `RUST_LOG` environment variable.
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
/// - Calling `log_init(None)` is equivalent to `log_init(option_env!("RUST_LOG"))`
/// - This function **can** be called from `#[tokio::test]` functions, unlike [`tracing_init`]
/// - ANSI colors are disabled by default
/// - Logs only to stdout (no files, syslog, or OTLP)
///
/// # Panics
///
/// Does not panic. If initialization fails, an error message is printed to stderr and
/// the function returns with minimal logging capability.
pub fn log_init(rust_log: Option<&str>) {
    let config = TracingConfig {
        otlp: None,
        service_name: String::new(),
        no_log_to_stdout: false,
        log_to_file: None,
        #[cfg(not(target_os = "windows"))]
        log_to_syslog: false,
        rust_log: rust_log
            .or(option_env!("RUST_LOG"))
            .map(std::borrow::ToOwned::to_owned),
        with_ansi_colors: false,
    };
    tracing_init(&config);
}
