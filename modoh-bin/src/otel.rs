use crate::{constants::OTEL_SERVICE_NAMESPACE, trace::OtelConfig};
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
  metrics::{
    reader::{DefaultAggregationSelector, DefaultTemporalitySelector},
    Instrument, MeterProvider, PeriodicReader, Stream,
  },
  runtime,
  trace::{BatchConfig, RandomIdGenerator, Sampler, Tracer},
  Resource,
};
use opentelemetry_semantic_conventions::{
  resource::{SERVICE_NAME, SERVICE_NAMESPACE, SERVICE_VERSION},
  SCHEMA_URL,
};

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

/// Construct MeterProvider for MetricsLayer
pub(crate) fn init_meter_provider<T>(otel_config: &OtelConfig<T>) -> MeterProvider
where
  T: Into<String> + Clone,
  opentelemetry::Value: From<T>,
{
  let otlp_endpoint = otel_config.otlp_endpoint.clone();
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
  let stdout_exporter = opentelemetry_stdout::MetricsExporter::default();
  let stdout_reader = PeriodicReader::builder(stdout_exporter, runtime::Tokio).build();

  // /* -------------- */
  // // TODO: Remove this block after implementing metrics
  // #[cfg(feature = "otel")]
  // {
  //   // metricsにおいて記録しておくkeyだけ指定するようにviewを設定
  //   info!(monotonic_counter.foo = 1_u64, key_1 = "bar", key_2 = 10, "handle foo",);
  //   info!(histogram.baz = 10, "histogram example",);
  // }
  // /* -------------- */
  /* ----------------- */
  // // Rename foo metrics to foo_named and drop key_2 attribute
  // let view_foo = |instrument: &Instrument| -> Option<Stream> {
  //   if instrument.name == "foo" {
  //     Some(
  //       Stream::new()
  //         .name("foo_named")
  //         .allowed_attribute_keys([Key::from("key_1")]),
  //     )
  //   } else {
  //     None
  //   }
  // };

  // // Set Custom histogram boundaries for baz metrics
  // let view_baz = |instrument: &Instrument| -> Option<Stream> {
  //   if instrument.name == "baz" {
  //     Some(
  //       Stream::new()
  //         .name("baz")
  //         .aggregation(Aggregation::ExplicitBucketHistogram {
  //           boundaries: vec![0.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0],
  //           record_min_max: true,
  //         }),
  //     )
  //   } else {
  //     None
  //   }
  // };
  // add prefix to metrics names
  // TODO: this setting removes description and units. Fix it.
  let view_prefix = |instrument: &Instrument| -> Option<Stream> {
    Some(Stream::new().name(format!("{}_{}", OTEL_SERVICE_NAMESPACE, instrument.name)))
  };
  /* ----------------- */

  let meter_provider = MeterProvider::builder()
    .with_resource(resource(otel_config))
    .with_reader(reader)
    .with_reader(stdout_reader)
    .with_view(view_prefix)
    .build();

  // Set global MeterProvider to use the meter_provider inside library
  global::set_meter_provider(meter_provider.clone());

  meter_provider
}

// Construct Tracer for OpenTelemetryLayer
pub(crate) fn init_tracer<T>(otel_config: &OtelConfig<T>) -> Tracer
where
  T: Into<String> + Clone,
  opentelemetry::Value: From<T>,
{
  let otlp_endpoint = otel_config.otlp_endpoint.clone();
  opentelemetry_otlp::new_pipeline()
    .tracing()
    .with_trace_config(
      opentelemetry_sdk::trace::Config::default()
        // Customize sampling strategy
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(1.0))))
        // If export trace to AWS X-Ray, you can use XrayIdGenerator
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource(otel_config)),
    )
    .with_batch_config(BatchConfig::default())
    .with_exporter(opentelemetry_otlp::new_exporter().tonic().with_endpoint(otlp_endpoint))
    .install_batch(runtime::Tokio)
    .unwrap()
}
