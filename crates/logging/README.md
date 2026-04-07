# ewqwe_logging

A comprehensive and flexible logging library for Rust applications, providing unified telemetry with support for multiple logging backends including stdout, file logging, syslog (Unix), and OpenTelemetry Protocol (OTLP).

## Features

- **Multiple Logging Backends**: Configure one or more output destinations simultaneously
  - Console/stdout with optional ANSI color support
  - Daily rolling file appender
  - Syslog integration (Unix/macOS/Linux)
  - OpenTelemetry Protocol (OTLP) for distributed tracing and metrics
  
- **OpenTelemetry Integration**: Full support for modern observability
  - Distributed tracing with gRPC-based OTLP exporter
  - Metrics collection with periodic export
  - Semantic conventions for service metadata
  - Customizable sampling and resource attributes
  
- **Flexible Configuration**: Fine-grained control over logging behavior
  - Environment-based filter configuration via `RUST_LOG`
  - Customizable service name, version, and environment tags
  - ANSI color output control
  - Configurable trace sampling and span limits

- **Production-Ready**: Built for reliability
  - Automatic cleanup of telemetry providers on shutdown
  - Protection against multiple initialization
  - Graceful error handling and fallbacks
  - Non-blocking file I/O

## Quick Start

### Basic Console Logging

For simple applications that only need stdout logging:

```rust
use ewqwe_logging::log_init;

fn main() {
    // Initialize with debug level
    log_init(Some("debug"));
    
    tracing::info!("Application started");
    tracing::debug!("Debug information");
}
```

### Advanced Telemetry Setup

For production applications with full observability:

```rust
use ewqwe_logging::{TracingConfig, TelemetryConfig, tracing_init};

#[tokio::main]
async fn main() {
    let config = TracingConfig {
        service_name: "my-service".to_string(),
        otlp: Some(TelemetryConfig {
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            environment: Some("production".to_string()),
            otlp_url: "http://localhost:4317".to_string(),
            enable_metering: true,
        }),
        no_log_to_stdout: false,
        #[cfg(not(target_os = "windows"))]
        log_to_syslog: true,
        log_to_file: Some((
            std::path::PathBuf::from("./logs"),
            "my-service".to_string()
        )),
        rust_log: Some("info,my_service=debug".to_string()),
        with_ansi_colors: true,
    };
    
    // Keep the guard alive for the lifetime of your application
    let _logging_guard = tracing_init(&config);
    
    // Your application code
    tracing::info!("Service initialized");
}
```

## Configuration Guide

### TracingConfig

The main configuration structure for initializing the logging system.

| Field | Type | Description |
|-------|------|-------------|
| `service_name` | `String` | Name of your service (used in OTLP and syslog) |
| `otlp` | `Option<TelemetryConfig>` | OpenTelemetry configuration (None disables OTLP) |
| `no_log_to_stdout` | `bool` | Set to true to disable console output |
| `log_to_syslog` | `bool` | Enable syslog output (Unix only) |
| `log_to_file` | `Option<(PathBuf, String)>` | Directory and filename prefix for daily log files |
| `rust_log` | `Option<String>` | Log filter string (e.g., "info,myapp=debug") |
| `with_ansi_colors` | `bool` | Enable colored output in console logs |

### TelemetryConfig

Configuration for OpenTelemetry Protocol (OTLP) integration.

| Field | Type | Description |
|-------|------|-------------|
| `version` | `Option<String>` | Service version (e.g., from CARGO_PKG_VERSION) |
| `environment` | `Option<String>` | Deployment environment (production, staging, dev) |
| `otlp_url` | `String` | OTLP collector endpoint (e.g., "<http://localhost:4317>") |
| `enable_metering` | `bool` | Enable metrics collection and export |

## Usage Examples

### File Logging with Daily Rotation

```rust
use ewqwe_logging::{TracingConfig, tracing_init};
use std::path::PathBuf;

let config = TracingConfig {
    service_name: "file-logger".to_string(),
    otlp: None,
    no_log_to_stdout: false,
    #[cfg(not(target_os = "windows"))]
    log_to_syslog: false,
    log_to_file: Some((
        PathBuf::from("./logs"),
        "application".to_string()
    )),
    rust_log: Some("info".to_string()),
    with_ansi_colors: false,
};

let _guard = tracing_init(&config);
// Logs will be written to ./logs/application.YYYY-MM-DD
```

### Distributed Tracing with OTLP

```rust
use ewqwe_logging::{TracingConfig, TelemetryConfig, tracing_init};
use tracing::{info, instrument};

#[tokio::main]
async fn main() {
    let config = TracingConfig {
        service_name: "distributed-app".to_string(),
        otlp: Some(TelemetryConfig {
            version: Some("1.0.0".to_string()),
            environment: Some("production".to_string()),
            otlp_url: "http://otlp-collector:4317".to_string(),
            enable_metering: false,  // Tracing only
        }),
        no_log_to_stdout: false,
        #[cfg(not(target_os = "windows"))]
        log_to_syslog: false,
        log_to_file: None,
        rust_log: Some("info".to_string()),
        with_ansi_colors: true,
    };
    
    let _guard = tracing_init(&config);
    
    process_request().await;
}

#[instrument]
async fn process_request() {
    info!("Processing request");
    // Tracing context is automatically propagated
}
```

### Recording Metrics

When `enable_metering` is true, you can record metrics using tracing macros:

```rust
use tracing::info;

// Counter metric
info!(
    monotonic_counter.requests_total = 1_u64,
    endpoint = "/api/users",
    "Request received"
);

// Histogram metric
info!(
    histogram.request_duration_ms = 142,
    "Request completed"
);

// Gauge metric  
info!(
    gauge.active_connections = 5_u64,
    "Connection pool status"
);
```

### Custom Log Filtering

Use the `RUST_LOG` environment variable or `rust_log` field for fine-grained control:

```rust
// Via configuration
let config = TracingConfig {
    rust_log: Some("warn,my_app::module=debug,other_crate=error".to_string()),
    // ... other fields
};

// Or via environment variable
// RUST_LOG=warn,my_app::module=debug cargo run
```

## OTLP Integration Details

### Filtering Internal Telemetry

When OTLP is enabled, the library automatically filters out noisy internal logs from:

- `hyper` (set to error level)
- `tonic` (set to error level)
- `h2` (disabled)
- `tower::buffer` (disabled)
- `opentelemetry-otlp` (disabled)
- `opentelemetry_sdk` (set to error level)

This prevents telemetry-induced-telemetry loops and reduces noise in your logs.

### Resource Attributes

The following semantic conventions are automatically applied:

- `service.name`: From `service_name` field
- `service.version`: From `TelemetryConfig.version`
- `deployment.environment.name`: From `TelemetryConfig.environment`

### Trace Configuration

Default trace settings:

- **Sampler**: AlwaysOn (all spans are sampled)
- **ID Generator**: Random
- **Max events per span**: 64
- **Max attributes per span**: 16
- **Export timeout**: 3 seconds

### Metrics Export

When metering is enabled:

- **Export interval**: 30 seconds
- **Temporality**: Default (Cumulative)
- **Debug output**: Metrics also exported to stdout (development aid)

## Error Handling

The library defines a comprehensive error type `LoggerError` with variants for:

- OTLP-related errors (connection, exporter building)
- Filter parsing errors
- Tracing subscriber initialization errors
- I/O errors (file logging)

Initialization errors are logged to stderr without panicking, allowing the application to continue with degraded logging capabilities.

## Important Notes

### Tokio Test Compatibility

The `tracing_init()` function cannot be used in tests marked with `#[tokio::test]` due to OTLP gRPC provider limitations. Use `log_init()` instead for testing:

```rust
#[tokio::test]
async fn my_test() {
    ewqwe_logging::log_init(Some("debug"));
    // test code
}
```

### Guard Lifetime

The `LoggingGuards` returned by `tracing_init()` must be kept alive for the entire application lifetime:

```rust
let _guard = tracing_init(&config);  // Keep underscore prefix to avoid unused variable warning
// Guard automatically shuts down telemetry providers when dropped
```

### Multiple Initialization Protection

The library prevents multiple initializations using an atomic flag. Subsequent calls to `tracing_init()` will log a warning and return an empty guard.

## Dependencies

Core dependencies include:

- `tracing` / `tracing-subscriber`: Logging framework
- `opentelemetry` / `opentelemetry-otlp`: OTLP integration
- `tracing-opentelemetry`: Bridge between tracing and OpenTelemetry
- `syslog-tracing`: Syslog backend (Unix)
- `tracing-appender`: File logging with rotation

## Architecture

The library is organized into modules:

- **`lib.rs`**: Public API (`log_init`, re-exports)
- **`tracing_bridge.rs`**: Main initialization logic, configuration types
- **`otlp.rs`**: OpenTelemetry provider setup (tracer and meter)
- **`error.rs`**: Error types and conversions

## License

See the workspace license file for details.
