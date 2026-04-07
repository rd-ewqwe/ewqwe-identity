//! Core tracing initialization and configuration.
//!
//! This module provides the main entry point for initializing the logging and telemetry
//! system. It handles the composition of multiple logging layers (stdout, files, syslog,
//! OpenTelemetry) into a unified tracing subscriber.
//!
//! # Architecture
//!
//! The initialization process follows these steps:
//!
//! 1. **Filter Configuration**: Set up `EnvFilter` with optional OTLP-specific suppressions
//! 2. **Layer Composition**: Build a stack of logging layers based on configuration
//! 3. **Provider Setup**: Initialize OpenTelemetry tracer and meter providers if enabled
//! 4. **Subscriber Registration**: Register the global tracing subscriber
//!
//! # Thread Safety
//!
//! The module uses an `AtomicBool` to prevent multiple initializations, which would
//! cause errors or undefined behavior.

use std::{
    env::set_var,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::{metrics::SdkMeterProvider, trace::SdkTracerProvider};
use tracing::debug;
use tracing::{info, span, warn};
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, reload, util::SubscriberInitExt};

use crate::LoggerError;
use crate::otlp;

static TRACING_SET: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Configuration Types
// ============================================================================

/// Main configuration for the tracing and logging system.
///
/// This structure controls all aspects of logging output including destination,
/// format, and OpenTelemetry integration.
///
/// # Examples
///
/// ## Minimal Configuration (stdout only)
///
/// ```
/// use ewqwe_logging::TracingConfig;
///
/// let config = TracingConfig {
///     service_name: "my-app".to_string(),
///     otlp: None,
///     no_log_to_stdout: false,
///     #[cfg(not(target_os = "windows"))]
///     log_to_syslog: false,
///     log_to_file: None,
///     rust_log: Some("info".to_string()),
///     with_ansi_colors: true,
/// };
/// ```
///
/// ## Full Production Configuration
///
/// ```
/// use ewqwe_logging::{TracingConfig, TelemetryConfig};
/// use std::path::PathBuf;
///
/// let config = TracingConfig {
///     service_name: "production-service".to_string(),
///     otlp: Some(TelemetryConfig {
///         version: Some(env!("CARGO_PKG_VERSION").to_string()),
///         environment: Some("production".to_string()),
///         otlp_url: "http://otlp-collector:4317".to_string(),
///         enable_metering: true,
///     }),
///     no_log_to_stdout: false,
///     #[cfg(not(target_os = "windows"))]
///     log_to_syslog: true,
///     log_to_file: Some((PathBuf::from("/var/log/myapp"), "service".to_string())),
///     rust_log: Some("info,myapp=debug".to_string()),
///     with_ansi_colors: false,
/// };
/// ```
#[derive(Debug, Default, Clone)]
pub struct TracingConfig {
    /// Name of the service using this configuration.
    ///
    /// Used by OTLP collector and syslog to identify the source of logs and traces.
    /// Should be a unique identifier for your service (e.g., "auth-service", "api-gateway").
    pub service_name: String,

    /// OpenTelemetry configuration for distributed tracing and metrics.
    ///
    /// Set to `None` to disable OTLP integration. When enabled, traces and optionally
    /// metrics will be exported to the configured OTLP collector endpoint.
    pub otlp: Option<TelemetryConfig>,

    /// Disable logging to stdout/stderr.
    ///
    /// Set to `true` to suppress console output. Useful in production environments
    /// where logs are only needed in files or external systems.
    pub no_log_to_stdout: bool,

    #[cfg(not(target_os = "windows"))]
    /// Enable logging to system syslog (Unix/Linux/macOS only).
    ///
    /// When enabled, logs will be sent to the system's syslog daemon with the
    /// service name as the syslog identity.
    pub log_to_syslog: bool,

    /// Enable daily rolling file logging.
    ///
    /// If set, logs will be written to `<directory>/<name>.YYYY-MM-DD`.
    /// A new file is created each day at midnight UTC.
    ///
    /// The tuple contains:
    /// - `PathBuf`: Directory path (will be created if it doesn't exist)
    /// - `String`: Base filename (date will be appended)
    ///
    /// Example: `Some((PathBuf::from("./logs"), "app".to_string()))` creates
    /// files like `./logs/app.2026-01-20`.
    pub log_to_file: Option<(PathBuf, String)>,

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

/// OpenTelemetry Protocol (OTLP) configuration for distributed tracing and metrics.
///
/// This structure configures the connection to an OTLP collector and defines
/// resource attributes for service identification.
///
/// # Examples
///
/// ```
/// use ewqwe_logging::TelemetryConfig;
///
/// let config = TelemetryConfig {
///     version: Some("1.2.3".to_string()),
///     environment: Some("production".to_string()),
///     otlp_url: "http://localhost:4317".to_string(),
///     enable_metering: true,
/// };
/// ```
#[derive(Debug, Default, Clone)]
pub struct TelemetryConfig {
    /// Service version for resource attributes.
    ///
    /// Typically set from `CARGO_PKG_VERSION` or a build-time constant.
    /// This appears as the `service.version` attribute in telemetry data.
    ///
    /// Example: `Some(env!("CARGO_PKG_VERSION").to_string())`
    pub version: Option<String>,

    /// Deployment environment name for resource attributes.
    ///
    /// Used to distinguish between different deployment stages.
    /// This appears as the `deployment.environment.name` attribute.
    ///
    /// Common values: "production", "staging", "development", "testing"
    pub environment: Option<String>,

    /// OTLP collector endpoint URL.
    ///
    /// Should be a gRPC endpoint (not HTTP). The protocol is always gRPC via Tonic.
    ///
    /// Examples:
    /// - Local: `"http://localhost:4317"`
    /// - Remote: `"http://otlp-collector.example.com:4317"`
    /// - TLS: `"https://secure-collector.example.com:4317"`
    pub otlp_url: String,

    /// Enable metrics collection and export.
    ///
    /// When `true`, both tracing and metrics are enabled. When `false`,
    /// only distributed tracing is active.
    ///
    /// Metrics are exported every 30 seconds to the OTLP collector.
    pub enable_metering: bool,
}

// ============================================================================
// Logging Guards and Cleanup
// ============================================================================

/// RAII guard for OpenTelemetry providers and file logging.
///
/// This structure holds ownership of telemetry providers and ensures they are
/// properly shut down when the guard is dropped. It's critical to keep this
/// guard alive for the lifetime of the application.
///
/// # Drop Behavior
///
/// When dropped, the guard will:
/// 1. Flush and shutdown the OTLP tracer provider
/// 2. Flush and shutdown the OTLP meter provider
/// 3. Close the file logging worker thread
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
pub struct LoggingGuards {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
    rolling_appender_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

impl Drop for LoggingGuards {
    fn drop(&mut self) {
        {
            if let Some(tracer_provider) = &mut self.tracer_provider {
                debug!("dropping OTLP tracer");
                if let Err(err) = tracer_provider.shutdown() {
                    eprintln!("Trace provider shutdown error: {err:?}");
                }
            }
            if let Some(meter_provider) = &mut self.meter_provider {
                debug!("dropping OTLP meter");
                if let Err(_err) = meter_provider.shutdown() {
                    // ignore the error
                }
            }
        }
    }
}

// ============================================================================
// Public Interface
// ============================================================================

/// Initialize the unified logging and telemetry system.
///
/// This is the main entry point for setting up logging in your application. It configures
/// and initializes all logging backends based on the provided configuration.
///
/// # Arguments
///
/// * `tracing_config` - Configuration structure defining logging behavior
///
/// # Returns
///
/// Returns a [`LoggingGuards`] RAII guard that **must** be kept alive for the entire
/// application lifetime. When dropped, it ensures proper shutdown of all telemetry
/// providers and file logging workers.
///
/// # Behavior
///
/// The function will:
/// 1. Set `RUST_LOG` and `RUST_BACKTRACE` environment variables if configured
/// 2. Initialize configured logging layers (stdout, files, syslog, OTLP)
/// 3. Set up log filtering based on `RUST_LOG` or config
/// 4. Register the global tracing subscriber
///
/// # Multiple Initialization Protection
///
/// This function can only be called once successfully. Subsequent calls will:
/// - Log a warning message
/// - Return an empty guard without re-initializing
/// - Not affect the existing logging setup
///
/// # Error Handling
///
/// If initialization fails:
/// - An error message is printed to stderr
/// - An empty guard is returned
/// - The application can continue with degraded logging
/// - The protection flag is reset to allow retry
///
/// # Important: Tokio Test Incompatibility
///
/// This function **cannot** be used in tests marked with `#[tokio::test]` due to
/// OTLP gRPC provider limitations. Use [`crate::log_init`] instead for testing.
///
/// # Examples
///
/// ## Basic Usage
///
/// ```no_run
/// use ewqwe_logging::{TracingConfig, tracing_init};
///
/// let config = TracingConfig {
///     service_name: "my-service".to_string(),
///     rust_log: Some("info".to_string()),
///     ..Default::default()
/// };
///
/// let _guard = tracing_init(&config);
///
/// tracing::info!("Application started");
/// // ... application code ...
/// ```
///
/// ## With Full OTLP Integration
///
/// ```no_run
/// use ewqwe_logging::{TracingConfig, TelemetryConfig, tracing_init};
///
/// let config = TracingConfig {
///     service_name: "api-server".to_string(),
///     otlp: Some(TelemetryConfig {
///         version: Some(env!("CARGO_PKG_VERSION").to_string()),
///         environment: Some("production".to_string()),
///         otlp_url: "http://localhost:4317".to_string(),
///         enable_metering: true,
///     }),
///     rust_log: Some("info,api_server=debug".to_string()),
///     with_ansi_colors: false,
///     ..Default::default()
/// };
///
/// let _guard = tracing_init(&config);
///
/// // Tracing and metrics are now active
/// tracing::info!("Server starting");
/// ```
///
/// ## Recording Metrics
///
/// ```no_run
/// use ewqwe_logging::{TracingConfig, TelemetryConfig, tracing_init};
///
/// let config = TracingConfig {
///     service_name: "metrics-example".to_string(),
///     otlp: Some(TelemetryConfig {
///         otlp_url: "http://localhost:4317".to_string(),
///         enable_metering: true,
///         ..Default::default()
///     }),
///     ..Default::default()
/// };
/// let _guard = tracing_init(&config);
///
/// // Counter
/// tracing::info!(monotonic_counter.requests = 1_u64, "Request handled");
///
/// // Histogram
/// tracing::info!(histogram.response_time_ms = 42, "Request completed");
///
/// // Gauge
/// tracing::info!(gauge.connections = 5_u64, "Connection pool status");
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
        Ok(otel_guard) => {
            let span = span!(tracing::Level::INFO, "tracing_init");
            let _guard = span.enter();
            info!("Tracing initialized with config {tracing_config:#?}",);
            otel_guard
        }
        Err(err) => {
            TRACING_SET.store(false, Ordering::Release);
            // If we cannot initialize the tracing system, we should not panic
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
/// across all logging layers (stdout, file, syslog).
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
/// This function performs the actual work of setting up the tracing subscriber
/// with all configured layers. It returns a Result to allow proper error handling
/// before the guard is created.
///
/// # Layer Initialization Order
///
/// 1. **Filter Layer**: EnvFilter with optional OTLP suppressions
/// 2. **Stdout Layer**: Optional console output (if not disabled)
/// 3. **File Layer**: Optional daily rolling file appender
/// 4. **Syslog Layer**: Optional syslog integration (Unix only)
/// 5. **OTLP Layer**: Optional OpenTelemetry tracing layer
/// 6. **Metrics Layer**: Optional OpenTelemetry metrics layer
///
/// # OTLP-Specific Filtering
///
/// When OTLP is enabled, additional filters suppress internal telemetry logs to
/// prevent feedback loops:
/// - `hyper=error`: HTTP client used by OTLP exporter
/// - `tonic=error`: gRPC framework
/// - `h2=off`: HTTP/2 protocol implementation
/// - `tower::buffer=off`: Middleware buffering
/// - `opentelemetry-otlp=off`: OTLP exporter internals
/// - `opentelemetry_sdk=error`: SDK internals
///
/// # Errors
///
/// Returns [`LoggerError`] if:
/// - Filter parsing fails
/// - Log directory creation fails
/// - OTLP provider initialization fails
/// - Tracing subscriber registration fails
fn tracing_init_(config: &TracingConfig) -> Result<LoggingGuards, LoggerError> {
    let mut otel_guard = LoggingGuards::default();
    let mut layers = vec![];

    // ========================================
    // Filter Configuration
    // ========================================
    let filter = {
        if config.otlp.is_some() {
            // ========================================
            // OTLP Filter Configuration
            // ========================================
            // To prevent a telemetry-induced-telemetry loop, OpenTelemetry's own internal
            // logging is properly suppressed. However, logs emitted by external components
            // (such as reqwest, tonic, etc.) are not suppressed as they do not propagate
            // OpenTelemetry context. Until this issue is addressed
            // (https://github.com/open-telemetry/opentelemetry-rust/issues/2877),
            // filtering like this is the best way to suppress such logs.
            //
            // The filter levels are set as follows:
            // - Allow `info` level and above by default.
            // - Completely restrict logs from `hyper`, `tonic`, `h2`, and `reqwest`.
            //
            // Note: This filtering will also drop logs from these components even when
            // they are used outside of the OTLP Exporter.
            let (filter, _reload_handle) = reload::Layer::new(
                EnvFilter::from_default_env()
                    .add_directive("hyper=error".parse()?)
                    .add_directive("tonic=error".parse()?)
                    .add_directive("tower::buffer=off".parse()?)
                    .add_directive("opentelemetry-otlp=off".parse()?)
                    .add_directive("opentelemetry_sdk=error".parse()?)
                    // .add_directive("reqwest=off".parse()?)
                    .add_directive("h2=off".parse()?),
            );
            filter
        } else {
            // If no OTLP URL is provided, we can use the default filter
            let (filter, _reload_handle) = reload::Layer::new(EnvFilter::from_default_env());
            filter
        }
    };

    // ========================================
    // Stdout Logging Layer
    // ========================================
    // Logging to stdout
    if !config.no_log_to_stdout {
        let fmt_layer = configure_fmt_layer!(
            tracing_subscriber::fmt::layer(),
            FmtConfig::standard(config.with_ansi_colors)
        )
        .compact();
        layers.push(fmt_layer.boxed());
    }

    // ========================================
    // File Logging Layer
    // ========================================
    // Logging the rolling file appender
    if let Some((dir, name)) = &config.log_to_file {
        // create the logs directory if it does not exist
        if !dir.exists() {
            std::fs::create_dir_all(dir).map_err(|err| {
                LoggerError::IOError(format!("Failed to create logs directory: {dir:?}: {err:?}"))
            })?;
        }

        // Configure a daily rolling file appender
        // Log files will be created in the "logs" directory
        // with names like "<name>.YYYY-MM-DD"
        let file_appender = tracing_appender::rolling::daily(dir, name);
        let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);
        otel_guard.rolling_appender_guard = Some(guard);

        let fmt_layer = configure_fmt_layer!(
            tracing_subscriber::fmt::layer().with_writer(non_blocking_writer),
            FmtConfig::standard(false) // No ANSI colors for file logs
        )
        .compact();
        layers.push(fmt_layer.boxed());
    }

    // ========================================
    // Syslog Logging Layer (Unix only)
    // ========================================
    // Logging to syslog
    #[cfg(not(target_os = "windows"))]
    if config.log_to_syslog {
        let identity =
            std::borrow::Cow::Owned(std::ffi::CString::new(config.service_name.clone())?);
        let (options, facility) = Default::default();
        if let Some(syslog) = syslog_tracing::Syslog::new(identity, options, facility) {
            let syslog_layer = configure_fmt_layer!(
                tracing_subscriber::fmt::layer().with_writer(syslog),
                FmtConfig::standard(false) // No ANSI colors for syslog
            );
            layers.push(syslog_layer.boxed());
        }
    }

    // ========================================
    // OpenTelemetry Logging Layer
    // ========================================
    // Logging to the OpenTelemetry collector
    if let Some(otlp_config) = &config.otlp {
        // The OpenTelemetry tracing provider
        let otlp_provider = otlp::init_tracer_provider(
            &config.service_name,
            &otlp_config.otlp_url,
            otlp_config.version.clone(),
            otlp_config.environment.clone(),
        )?;
        layers.push(
            OpenTelemetryLayer::new(otlp_provider.tracer(config.service_name.clone())).boxed(),
        );

        let meter_provider = otlp_config
            .enable_metering
            .then(|| {
                otlp::init_meter_provider(
                    &config.service_name,
                    &otlp_config.otlp_url,
                    otlp_config.version.clone(),
                    otlp_config.environment.clone(),
                )
                .inspect(|meter_provider| {
                    layers.push(MetricsLayer::new(meter_provider.clone()).boxed());
                })
            })
            .transpose()?;

        otel_guard.tracer_provider = Some(otlp_provider);
        otel_guard.meter_provider = meter_provider;
    }

    // ========================================
    // Initialize Tracing Subscriber
    // ========================================
    // Initialize the global tracing subscriber
    tracing_subscriber::registry()
        .with(filter)
        .with(layers)
        .try_init()?;

    Ok(otel_guard)
}
