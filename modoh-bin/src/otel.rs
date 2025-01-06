use crate::{constants::OTEL_SERVICE_NAMESPACE, trace::OtelConfig};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, Resource};
use opentelemetry_semantic_conventions::{
  resource::{SERVICE_NAME, SERVICE_NAMESPACE, SERVICE_VERSION},
  SCHEMA_URL,
};

#[cfg(feature = "otel-trace")]
use opentelemetry_sdk::trace::{BatchConfigBuilder, Builder as SdkBuilder, RandomIdGenerator, Sampler, Tracer};

#[cfg(feature = "otel-trace")]
use opentelemetry::trace::TracerProvider;

#[cfg(feature = "otel-metrics")]
use opentelemetry_sdk::metrics::{Instrument, PeriodicReader, SdkMeterProvider, Stream, Temporality};

#[cfg(any(feature = "otel-metrics", feature = "otel-trace"))]
use opentelemetry::global;

#[cfg(feature = "otel-instance-id")]
use opentelemetry_semantic_conventions::resource::SERVICE_INSTANCE_ID;

// Create a Resource that captures information about the entity for which telemetry is recorded.
pub(crate) fn resource<T>(_otel_config: &OtelConfig<T>) -> Resource
where
  T: Into<String> + Clone,
  opentelemetry::Value: From<T>,
{
  Resource::from_schema_url(
    [
      KeyValue::new(SERVICE_NAMESPACE, OTEL_SERVICE_NAMESPACE),
      KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
      KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
      #[cfg(feature = "otel-instance-id")]
      KeyValue::new(SERVICE_INSTANCE_ID, _otel_config.service_instance_id.clone().into()),
    ],
    SCHEMA_URL,
  )
}

#[cfg(feature = "otel-metrics")]
/// Construct SdkMeterProvider for MetricsLayer
pub(crate) fn init_meter_provider<T>(otel_config: &OtelConfig<T>) -> SdkMeterProvider
where
  T: Into<String> + Clone,
  opentelemetry::Value: From<T>,
{
  use opentelemetry_sdk::metrics::Aggregation;

  let otlp_endpoint = otel_config.otlp_endpoint.clone();
  // exporter via otlp
  let exporter = opentelemetry_otlp::MetricExporter::builder()
    .with_tonic()
    .with_endpoint(otlp_endpoint)
    .with_temporality(Temporality::default())
    .build()
    .unwrap();

  let reader = PeriodicReader::builder(exporter, runtime::Tokio)
    .with_interval(std::time::Duration::from_secs(30))
    .build();

  // For debugging in development
  let stdout_exporter = opentelemetry_stdout::MetricExporter::default();
  let stdout_reader = PeriodicReader::builder(stdout_exporter, runtime::Tokio).build();

  // define view
  let view = |instrument: &Instrument| -> Option<Stream> {
    // add prefix to metrics names
    let stream = Stream::new()
      .name(format!("{}_{}", OTEL_SERVICE_NAMESPACE, instrument.name)) // add prefix to metrics names
      .description(instrument.description.clone())
      .unit(instrument.unit.clone());

    if instrument.name.contains("latency_") {
      Some(stream.aggregation(Aggregation::ExplicitBucketHistogram {
        boundaries: vec![25.0, 50.0, 100.0, 200.0, 400.0, 800.0, 1600.0, 3200.0],
        record_min_max: true,
      }))
    } else {
      Some(stream)
    }
  };

  let meter_provider = SdkMeterProvider::builder()
    .with_resource(resource(otel_config))
    .with_reader(reader)
    .with_reader(stdout_reader)
    .with_view(view)
    .build();

  // Set global MeterProvider to use the meter_provider inside library
  global::set_meter_provider(meter_provider.clone());

  meter_provider
}

#[cfg(feature = "otel-trace")]
// Construct Tracer for OpenTelemetryLayer
pub(crate) fn init_tracer<T>(otel_config: &OtelConfig<T>) -> Tracer
where
  T: Into<String> + Clone,
  opentelemetry::Value: From<T>,
{
  let otlp_endpoint = otel_config.otlp_endpoint.clone();
  let exporter = opentelemetry_otlp::SpanExporter::builder()
    .with_tonic()
    .with_endpoint(otlp_endpoint)
    .build()
    .unwrap();
  let batch_processor = opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter, runtime::Tokio)
    .with_batch_config(
      BatchConfigBuilder::default()
        .with_max_queue_size(crate::constants::OTEL_TRACE_BATCH_QUEUE_SIZE)
        .build(),
    )
    .build();

  let provider = SdkBuilder::default()
    .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(1.0))))
    .with_id_generator(RandomIdGenerator::default())
    .with_resource(resource(otel_config))
    .with_span_processor(batch_processor)
    .build();

  global::set_tracer_provider(provider.clone());
  provider.tracer("modoh-server")
}
