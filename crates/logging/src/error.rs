//! Error types for the logging library.
//!
//! This module defines the [`LoggerError`] enum which encompasses all possible errors
//! that can occur during logging initialization and operation.

use thiserror::Error;

/// Errors that can occur during logging system initialization and operation.
///
/// This enum provides comprehensive error handling for various logging backends
/// and configuration issues.
#[derive(Error, Debug)]
pub enum LoggerError {
    /// An error occurred in the OpenTelemetry OTLP provider.
    ///
    /// This typically indicates issues with:
    /// - Connecting to the OTLP collector endpoint
    /// - Building the OTLP exporter
    /// - Network connectivity to the telemetry backend
    #[error("OTLP error: {0}")]
    Otlp(String),

    /// An error occurred while parsing configuration or filter strings.
    ///
    /// This can happen when:
    /// - Invalid `RUST_LOG` filter syntax is provided
    /// - Malformed configuration strings are encountered
    #[error("Parsing error: {0}")]
    Parsing(String),

    /// An error occurred during tracing subscriber initialization.
    ///
    /// This typically means:
    /// - The global subscriber has already been set
    /// - Multiple initialization attempts
    #[error("Tracing subscriber error: {0}")]
    TracingSubscriber(String),

    /// An I/O error occurred during file logging operations.
    ///
    /// This can happen when:
    /// - Log directory cannot be created
    /// - Insufficient permissions for file operations
    /// - Disk space issues
    #[error("IO error: {0}")]
    IOError(String),
}

impl From<opentelemetry_otlp::ExporterBuildError> for LoggerError {
    fn from(e: opentelemetry_otlp::ExporterBuildError) -> Self {
        Self::Otlp(e.to_string())
    }
}

impl From<tracing_subscriber::filter::ParseError> for LoggerError {
    fn from(e: tracing_subscriber::filter::ParseError) -> Self {
        Self::Parsing(e.to_string())
    }
}

impl From<tracing_subscriber::util::TryInitError> for LoggerError {
    fn from(value: tracing_subscriber::util::TryInitError) -> Self {
        Self::TracingSubscriber(value.to_string())
    }
}

impl From<std::ffi::NulError> for LoggerError {
    fn from(e: std::ffi::NulError) -> Self {
        Self::Parsing(e.to_string())
    }
}
