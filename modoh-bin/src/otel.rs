use crate::{constants::OTEL_SERVICE_NAMESPACE, trace::TraceConfig};
use opentelemetry::{global, Key, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
  metrics::{
    reader::{DefaultAggregationSelector, DefaultTemporalitySelector},
    Aggregation, Instrument, MeterProvider, PeriodicReader, Stream,
  },
  runtime,
  trace::{BatchConfig, RandomIdGenerator, Sampler, Tracer},
  Resource,
};
use opentelemetry_semantic_conventions::{
  resource::{SERVICE_NAME, SERVICE_NAMESPACE, SERVICE_VERSION},
  SCHEMA_URL,
};

// Create a Resource that captures information about the entity for which telemetry is recorded.
pub(crate) fn resource<T>(trace_config: &TraceConfig<T>) -> Resource
where
  T: Into<String> + Clone,
  opentelemetry::Value: From<T>,
{
  Resource::from_schema_url(
    [
      KeyValue::new(SERVICE_NAMESPACE, OTEL_SERVICE_NAMESPACE),
      KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
      KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
    ],
    SCHEMA_URL,
  )
}

/// Construct MeterProvider for MetricsLayer
pub(crate) fn init_meter_provider<T>(trace_config: &TraceConfig<T>) -> MeterProvider
where
  T: Into<String> + Clone,
  opentelemetry::Value: From<T>,
{
  let otlp_endpoint = trace_config.otel_config.as_ref().unwrap().otlp_endpoint.clone();
  // exporter via otlp
  let exporter = opentelemetry_otlp::new_exporter()
    .tonic()
    .with_endpoint(otlp_endpoint)
    .build_metrics_exporter(
      Box::new(DefaultAggregationSelector::new()),
      Box::new(DefaultTemporalitySelector::new()),
    )
    .unwrap();

  let reader = PeriodicReader::builder(exporter, runtime::Tokio)
    .with_interval(std::time::Duration::from_secs(30))
    .build();

  // For debugging in development
  let stdout_exporter = opentelemetry_stdout::MetricsExporterBuilder::default()
    .with_encoder(|writer, data| {
      serde_json::to_writer_pretty(writer, &data).unwrap();
      Ok(())
    })
    .build();
  let stdout_reader = PeriodicReader::builder(stdout_exporter, runtime::Tokio).build();

  /* ----------------- */
  // Rename foo metrics to foo_named and drop key_2 attribute
  let view_foo = |instrument: &Instrument| -> Option<Stream> {
    if instrument.name == "foo" {
      Some(
        Stream::new()
          .name("foo_named")
          .allowed_attribute_keys([Key::from("key_1")]),
      )
    } else {
      None
    }
  };

  // Set Custom histogram boundaries for baz metrics
  let view_baz = |instrument: &Instrument| -> Option<Stream> {
    if instrument.name == "baz" {
      Some(
        Stream::new()
          .name("baz")
          .aggregation(Aggregation::ExplicitBucketHistogram {
            boundaries: vec![0.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0],
            record_min_max: true,
          }),
      )
    } else {
      None
    }
  };
  /* ----------------- */

  let meter_provider = MeterProvider::builder()
    .with_resource(resource(trace_config))
    .with_reader(reader)
    .with_reader(stdout_reader)
    .with_view(view_foo)
    .with_view(view_baz)
    .build();

  global::set_meter_provider(meter_provider.clone());

  meter_provider
}

// Construct Tracer for OpenTelemetryLayer
pub(crate) fn init_tracer<T>(trace_config: &TraceConfig<T>) -> Tracer
where
  T: Into<String> + Clone,
  opentelemetry::Value: From<T>,
{
  let otlp_endpoint = trace_config.otel_config.as_ref().unwrap().otlp_endpoint.clone();
  opentelemetry_otlp::new_pipeline()
    .tracing()
    .with_trace_config(
      opentelemetry_sdk::trace::Config::default()
        // Customize sampling strategy
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(1.0))))
        // If export trace to AWS X-Ray, you can use XrayIdGenerator
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource(trace_config)),
    )
    .with_batch_config(BatchConfig::default())
    .with_exporter(opentelemetry_otlp::new_exporter().tonic().with_endpoint(otlp_endpoint))
    .install_batch(runtime::Tokio)
    .unwrap()
}
