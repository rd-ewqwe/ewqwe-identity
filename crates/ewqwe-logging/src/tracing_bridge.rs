//! Core tracing initialization and configuration.
//!
//! This module provides the main entry point for initializing the logging
//! system with stdout output.

use std::{
    env::set_var,
    sync::atomic::{AtomicBool, Ordering},
};

use tracing::{info, span, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::LoggerError;

static TRACING_SET: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Configuration Types
// ============================================================================

/// Main configuration for the tracing and logging system.
///
/// This structure controls stdout logging output and formatting.
///
/// # Examples
///
/// ```
/// use ewqwe_logging::TracingConfig;
///
/// let config = TracingConfig {
///     rust_log: Some("info".to_string()),
///     with_ansi_colors: true,
/// };
/// ```
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TracingConfig {
    /// Default log filter configuration.
    ///
    /// If set, this overrides the `RUST_LOG` environment variable. The syntax follows
    /// the `tracing_subscriber::EnvFilter` format:
    ///
    /// - `"info"`: Set global level to info
    /// - `"debug,hyper=info"`: Debug globally, info for hyper crate
    /// - `"myapp::module=trace"`: Trace level for specific module
    ///
    /// If `None`, the `RUST_LOG` environment variable is used.
    pub rust_log: Option<String>,

    /// Enable ANSI color codes in stdout logs.
    ///
    /// Set to `true` for colored terminal output. Should be `false` when logging
    /// to files or systems that don't support ANSI codes.
    pub with_ansi_colors: bool,
}

// ============================================================================
// Logging Guards and Cleanup
// ============================================================================

/// RAII guard for the logging system.
///
/// This structure follows the guard pattern to own any resources that need
/// to be kept alive for the application lifetime. In the stdout-only version,
/// the guard is empty — it exists to maintain API compatibility and allow
/// future extensions.
///
/// # Examples
///
/// ```no_run
/// use ewqwe_logging::{TracingConfig, tracing_init};
/// let config = TracingConfig::default();
///
/// // Keep the guard alive for the entire program
/// let _guard = tracing_init(&config);
/// ```
#[derive(Default)]
pub struct LoggingGuards {}

impl Drop for LoggingGuards {
    fn drop(&mut self) {}
}

// ============================================================================
// Public Interface
// ============================================================================

/// Initialize stdout-only tracing with the given configuration.
///
/// This is the main entry point for setting up logging in your application.
/// It configures and initializes a stdout-based tracing subscriber.
///
/// # Arguments
///
/// * `tracing_config` - Configuration structure defining logging behavior
///
/// # Returns
///
/// Returns a [`LoggingGuards`] RAII guard that **must** be kept alive for the entire
/// application lifetime.
///
/// # Behavior
///
/// The function will:
/// 1. Set `RUST_LOG` and `RUST_BACKTRACE` environment variables if configured
/// 2. Initialize a stdout logging layer with the configured format
/// 3. Register the global tracing subscriber
///
/// # Multiple Initialization Protection
///
/// This function can only be called once successfully. Subsequent calls will:
/// - Log a warning message
/// - Return an empty guard without re-initializing
/// - Not affect the existing logging setup
///
/// # Examples
///
/// ```no_run
/// use ewqwe_logging::{TracingConfig, tracing_init};
///
/// let config = TracingConfig {
///     rust_log: Some("info".to_string()),
///     ..Default::default()
/// };
///
/// let _guard = tracing_init(&config);
///
/// tracing::info!("Application started");
/// ```
pub fn tracing_init(tracing_config: &TracingConfig) -> LoggingGuards {
    // Set the RUST_LOG environment variable if a config value is provided
    if let Some(rust_log) = &tracing_config.rust_log {
        unsafe { set_var("RUST_LOG", rust_log) };
    }

    // Enable backtraces for all errors
    unsafe { set_var("RUST_BACKTRACE", "full") };

    if TRACING_SET.swap(true, Ordering::Acquire) {
        let span = span!(tracing::Level::INFO, "tracing_init");
        let _guard = span.enter();
        warn!("Tracing already initialized or crashed");
        return LoggingGuards::default();
    }

    match tracing_init_(tracing_config) {
        Ok(guard) => {
            let span = span!(tracing::Level::INFO, "tracing_init");
            let _guard = span.enter();
            info!("Tracing initialized with config {tracing_config:#?}");
            guard
        }
        Err(err) => {
            TRACING_SET.store(false, Ordering::Release);
            eprintln!("Failed to initialize tracing: {err:?}");
            LoggingGuards::default()
        }
    }
}

// ============================================================================
// Internal Implementation
// ============================================================================

/// Configuration for fmt layer formatting options.
///
/// Internal structure to standardize formatting across different logging layers.
#[derive(Clone, Copy)]
struct FmtConfig {
    with_level: bool,
    with_target: bool,
    with_thread_ids: bool,
    with_line_number: bool,
    with_file: bool,
    with_ansi: bool,
}

impl FmtConfig {
    /// Create a standard fmt layer configuration with customizable ANSI colors.
    ///
    /// Returns a configuration that includes:
    /// - Log levels
    /// - Target module information
    /// - Thread IDs
    /// - Line numbers
    /// - File names
    /// - Optional ANSI color codes
    const fn standard(with_ansi: bool) -> Self {
        Self {
            with_level: true,
            with_target: true,
            with_thread_ids: true,
            with_line_number: true,
            with_file: true,
            with_ansi,
        }
    }
}

/// Apply standard fmt layer configuration using a macro.
///
/// This macro centralizes the formatting configuration to ensure consistency
/// across logging layers.
macro_rules! configure_fmt_layer {
    ($layer:expr, $config:expr) => {{
        $layer
            .with_level($config.with_level)
            .with_target($config.with_target)
            .with_thread_ids($config.with_thread_ids)
            .with_line_number($config.with_line_number)
            .with_file($config.with_file)
            .with_ansi($config.with_ansi)
    }};
}

/// Internal implementation of tracing initialization.
///
/// Sets up the tracing subscriber with a stdout layer and env-filter based
/// log filtering.
///
/// # Errors
///
/// Returns [`LoggerError`] if:
/// - Filter parsing fails
/// - Tracing subscriber registration fails
fn tracing_init_(config: &TracingConfig) -> Result<LoggingGuards, LoggerError> {
    let filter = EnvFilter::from_default_env();

    let fmt_layer = configure_fmt_layer!(
        tracing_subscriber::fmt::layer(),
        FmtConfig::standard(config.with_ansi_colors)
    )
    .compact();

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init()?;

    Ok(LoggingGuards::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracing_config_serde_roundtrip() {
        let cfg = TracingConfig {
            rust_log: Some("info".to_string()),
            with_ansi_colors: true,
        };

        let json = serde_json::to_string(&cfg).expect("serialize tracing config");
        let cfg2: TracingConfig =
            serde_json::from_str(&json).expect("deserialize tracing config");

        assert_eq!(cfg.rust_log, cfg2.rust_log);
        assert_eq!(cfg.with_ansi_colors, cfg2.with_ansi_colors);
    }

    #[test]
    fn tracing_config_serde_with_toml() {
        let cfg = TracingConfig {
            rust_log: Some("debug".to_string()),
            with_ansi_colors: false,
        };

        let toml = toml::to_string(&cfg).expect("serialize tracing config to toml");
        let cfg2: TracingConfig =
            toml::from_str(&toml).expect("deserialize tracing config from toml");

        assert_eq!(cfg.rust_log, cfg2.rust_log);
        assert_eq!(cfg.with_ansi_colors, cfg2.with_ansi_colors);
    }
}
