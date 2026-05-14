//! OpenTelemetry Protocol (OTLP) provider initialization.
//!
//! This module handles the setup of OpenTelemetry tracer and meter providers
//! for distributed tracing and metrics collection. It configures:
//!
//! - **Tracer Provider**: Exports trace spans to an OTLP collector via gRPC
//! - **Meter Provider**: Exports metrics with periodic collection
//! - **Resource Attributes**: Semantic conventions for service metadata
//!
//! # Architecture
//!
//! The module provides internal functions that are called by the main tracing
//! initialization logic in `tracing_bridge.rs`. These functions:
//!
//! 1. Build OTLP exporters with gRPC/Tonic transport
//! 2. Configure sampling, ID generation, and resource attributes
//! 3. Register providers globally for use by tracing layers
//!
//! # Configuration
//!
//! Both tracer and meter providers use the same resource configuration,
//! which includes service name, version, and deployment environment.

use std::time::Duration;

use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider},
    trace::{RandomIdGenerator, Sampler, SdkTracerProvider},
};
use opentelemetry_semantic_conventions::{
    SCHEMA_URL,
    attribute::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_NAME, SERVICE_VERSION},
};

use crate::LoggerError;

/// Create an OpenTelemetry resource with semantic conventions.
///
/// Resources represent the entity producing telemetry and are attached to all
/// exported spans and metrics.
///
/// # Arguments
///
/// * `service_name` - The name of the service (required)
/// * `version` - Optional service version (e.g., from `CARGO_PKG_VERSION`)
/// * `environment` - Optional deployment environment (e.g., "production", "staging")
///
/// # Semantic Conventions
///
/// This function applies the following attributes:
/// - `service.name`: Service identifier
/// - `service.version`: Service version (if provided)
/// - `deployment.environment.name`: Environment name (if provided)
fn resource(service_name: &str, version: Option<String>, environment: Option<String>) -> Resource {
    let mut attributes = vec![KeyValue::new(SERVICE_NAME, service_name.to_owned())];
    if let Some(version) = version {
        attributes.push(KeyValue::new(SERVICE_VERSION, version));
    }
    if let Some(environment) = environment {
        attributes.push(KeyValue::new(DEPLOYMENT_ENVIRONMENT_NAME, environment));
    }
    Resource::builder()
        .with_service_name(service_name.to_owned())
        .with_schema_url(attributes, SCHEMA_URL)
        .build()
}

/// Initialize the OpenTelemetry tracer provider for distributed tracing.
///
/// This function creates and configures an OTLP tracer provider that exports
/// trace spans to a remote collector via gRPC.
///
/// # Arguments
///
/// * `service_name` - Name of the service generating traces
/// * `url` - OTLP collector endpoint (e.g., "http://localhost:4317")
/// * `version` - Optional service version for resource attributes
/// * `environment` - Optional deployment environment for resource attributes
///
/// # Configuration
///
/// The tracer provider is configured with:
/// - **Exporter**: gRPC/Tonic with 3-second timeout
/// - **Sampler**: AlwaysOn (all spans are sampled)
/// - **ID Generator**: Random (RFC 4122 compliant)
/// - **Max events per span**: 64
/// - **Max attributes per span**: 16
///
/// # Returns
///
/// Returns `Ok(SdkTracerProvider)` on success, which is then registered globally.
///
/// # Errors
///
/// Returns [`LoggerError::Otlp`] if:
/// - The OTLP endpoint is unreachable
/// - The exporter cannot be built
/// - Network or configuration issues occur
///
/// # Note
///
/// The provider is automatically registered as the global tracer provider.
pub(crate) fn init_tracer_provider(
    service_name: &str,
    url: &str,
    version: Option<String>,
    environment: Option<String>,
) -> Result<SdkTracerProvider, LoggerError> {
    let otlp_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(url.to_owned())
        .with_timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| {
            LoggerError::Otlp(format!(
                "Failed to create OTLP provider exporter. Make sure the endpoint is correct and \
                 the server is running: {e}"
            ))
        })?;

    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(otlp_exporter)
        .with_id_generator(RandomIdGenerator::default())
        .with_sampler(Sampler::AlwaysOn)
        .with_resource(resource(service_name, version, environment))
        .with_max_events_per_span(64)
        .with_max_attributes_per_span(16)
        .build();

    global::set_tracer_provider(tracer_provider.clone());

    Ok(tracer_provider)
}

/// Initialize the OpenTelemetry meter provider for metrics collection.
///
/// This function creates and configures an OTLP meter provider that exports
/// metrics to a remote collector via gRPC with periodic collection.
///
/// # Arguments
///
/// * `service_name` - Name of the service generating metrics
/// * `url` - OTLP collector endpoint (e.g., "http://localhost:4317")
/// * `version` - Optional service version for resource attributes
/// * `environment` - Optional deployment environment for resource attributes
///
/// # Configuration
///
/// The meter provider is configured with:
/// - **Primary Exporter**: gRPC/Tonic with 30-second export interval
/// - **Debug Exporter**: Stdout exporter for development visibility
/// - **Temporality**: Default (Cumulative) aggregation
///
/// # Returns
///
/// Returns `Ok(SdkMeterProvider)` on success, which is then registered globally.
///
/// # Errors
///
/// Returns [`LoggerError::Otlp`] if:
/// - The OTLP endpoint is unreachable
/// - The exporter cannot be built
/// - Network or configuration issues occur
///
/// # Note
///
/// - The provider is automatically registered as the global meter provider
/// - Metrics are exported every 30 seconds
/// - A stdout reader is included for debugging in development
pub(crate) fn init_meter_provider(
    service_name: &str,
    url: &str,
    version: Option<String>,
    environment: Option<String>,
) -> Result<SdkMeterProvider, LoggerError> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_temporality(opentelemetry_sdk::metrics::Temporality::default())
        .with_endpoint(url.to_owned())
        .build()
        .map_err(|e| {
            LoggerError::Otlp(format!(
                "Failed to create OTLP meter exporter. Make sure the endpoint is correct and the \
                 server is running: {e}"
            ))
        })?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(30))
        .build();

    // For debugging in development
    let stdout_reader =
        PeriodicReader::builder(opentelemetry_stdout::MetricExporter::default()).build();

    let meter_provider = MeterProviderBuilder::default()
        .with_resource(resource(service_name, version, environment))
        .with_reader(reader)
        .with_reader(stdout_reader)
        .build();

    global::set_meter_provider(meter_provider.clone());

    Ok(meter_provider)
}
