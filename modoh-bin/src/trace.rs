use opentelemetry_sdk::metrics::MeterProvider;
pub use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[cfg(feature = "otel")]
use crate::otel::{init_meter_provider, init_tracer};
#[cfg(feature = "otel")]
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};

/// Initialize tracing subscriber
pub fn init_tracing_subscriber(_trace_config: &TraceConfig<String>) -> MetricsGuard {
  let format_layer = fmt::layer()
    .with_line_number(false)
    .with_thread_ids(false)
    .with_thread_names(true)
    .with_target(true)
    .with_level(true)
    .compact();

  // This limits the logger to emits only this crate
  let pkg_name = env!("CARGO_PKG_NAME").replace('-', "_");
  let level_string = std::env::var(EnvFilter::DEFAULT_ENV).unwrap_or_else(|_| "info".to_string());
  let filter_layer = EnvFilter::new(format!("{}={}", pkg_name, level_string));
  // let filter_layer = EnvFilter::try_from_default_env()
  // .unwrap_or_else(|_| EnvFilter::new("info"))
  // .add_directive(format!("{}=trace", pkg_name).parse().unwrap());

  let reg = tracing_subscriber::registry().with(format_layer).with(filter_layer);

  #[cfg(feature = "otel")]
  {
    if _trace_config.otel_config.is_none() {
      reg.init();
      MetricsGuard { meter_provider: None }
    } else {
      println!("Opentelemetry is enabled for metrics and traces");
      let otel_config = _trace_config.otel_config.as_ref().unwrap();
      let meter_provider = init_meter_provider(otel_config);
      reg
        .with(MetricsLayer::new(meter_provider.clone()))
        .with(OpenTelemetryLayer::new(init_tracer(otel_config)))
        .init();
      MetricsGuard {
        meter_provider: Some(meter_provider),
      }
    }
  }
  #[cfg(not(feature = "otel"))]
  {
    reg.init();
    MetricsGuard {}
  }
}

/// Tracing config
pub(crate) struct TraceConfig<T> {
  #[cfg(feature = "otel")]
  pub(crate) otel_config: Option<OtelConfig<T>>,
  pub(crate) _marker: std::marker::PhantomData<fn() -> T>,
}

#[cfg(feature = "otel")]
/// Observability config
pub(crate) struct OtelConfig<T> {
  pub(crate) otlp_endpoint: T,
  #[cfg(feature = "otel-instance-id")]
  pub(crate) service_instance_id: T,
}

/// Guard for opentelemetry metrics
pub struct MetricsGuard {
  #[cfg(feature = "otel")]
  pub meter_provider: Option<MeterProvider>,
}

#[cfg(feature = "otel")]
impl Drop for MetricsGuard {
  fn drop(&mut self) {
    if self.meter_provider.is_none() {
      return;
    }
    let mp = self.meter_provider.take().unwrap();
    if let Err(err) = mp.shutdown() {
      eprintln!("{err:?}");
    }
    opentelemetry::global::shutdown_tracer_provider();
  }
}
