// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Telemetry initialization: log format selection and OpenTelemetry tracing.
//!
//! Supports two log formats controlled by `VOUCH_LOG_FORMAT`:
//! - `text` (default): human-readable output for local development
//! - `json`: structured JSON for K8s log pipelines (Fluent Bit, CloudWatch)
//!
//! OpenTelemetry distributed tracing is activated when `OTEL_EXPORTER_OTLP_ENDPOINT`
//! is set. When unset, no OTel layer is created and there is no overhead.

use std::sync::OnceLock;

use anyhow::Result;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use crate::config::LogFormat;

/// Global tracer provider stored for shutdown.
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Initialize the tracing subscriber with the specified log format and
/// optional OpenTelemetry integration.
///
/// # Errors
///
/// Returns an error if the OpenTelemetry tracer cannot be initialized.
pub fn init_tracing(log_format: LogFormat) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let otel_layer = init_opentelemetry()?;

    // Build the subscriber with optional layers.
    // The OTel layer is added first (closest to the registry) so its
    // generic parameter S = Registry is satisfied.
    match log_format {
        LogFormat::Text => {
            let fmt_layer = tracing_subscriber::fmt::layer();
            tracing_subscriber::registry()
                .with(otel_layer)
                .with(env_filter)
                .with(fmt_layer)
                .init();
        }
        LogFormat::Json => {
            let fmt_layer = tracing_subscriber::fmt::layer().json();
            tracing_subscriber::registry()
                .with(otel_layer)
                .with(env_filter)
                .with(fmt_layer)
                .init();
        }
    }

    Ok(())
}

/// Initialize OpenTelemetry if `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
///
/// Returns `None` if the env var is unset (no overhead).
fn init_opentelemetry() -> Result<
    Option<
        tracing_opentelemetry::OpenTelemetryLayer<
            tracing_subscriber::Registry,
            opentelemetry_sdk::trace::SdkTracer,
        >,
    >,
> {
    if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_err() {
        return Ok(None);
    }

    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "vouch-server".to_string());

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build OTLP exporter: {e}"))?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service_name)
                .build(),
        )
        .build();

    let tracer = provider.tracer("vouch-server");

    // Store provider for shutdown; OnceLock::set returning Err means it was already
    // set, which is fine on repeat init.
    let _set = TRACER_PROVIDER.set(provider);

    let layer = tracing_opentelemetry::OpenTelemetryLayer::new(tracer);
    Ok(Some(layer))
}

/// Flush pending OpenTelemetry spans and shut down the tracer provider.
///
/// Call this during graceful shutdown to ensure all traces are exported.
pub fn shutdown_tracing() {
    if let Some(provider) = TRACER_PROVIDER.get()
        && let Err(e) = provider.shutdown()
    {
        tracing::warn!("Failed to shutdown OpenTelemetry tracer provider: {e}");
    }
}
