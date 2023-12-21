pub use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[cfg(feature = "otel")]
use crate::otel::{init_meter_provider, init_tracer};
#[cfg(feature = "otel")]
use opentelemetry_sdk::metrics::MeterProvider;
#[cfg(feature = "otel")]
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};

/// Initialize tracing subscriber
pub fn init_tracing_subscriber(_trace_config: &TraceConfig<String>) -> Guard {
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
      Guard { meter_provider: None }
    } else {
      println!("Opentelemetry is enabled for metrics and traces");
      let meter_provider = init_meter_provider(_trace_config);
      reg
        .with(MetricsLayer::new(meter_provider.clone()))
        .with(OpenTelemetryLayer::new(init_tracer(_trace_config)))
        .init();
      Guard {
        meter_provider: Some(meter_provider),
      }
    }
  }
  #[cfg(not(feature = "otel"))]
  {
    reg.init();
    Guard {}
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
  pub(crate) hostname: T,
  pub(crate) deployment_environment: T,
}

/// Guard for tracing subscriber
pub(crate) struct Guard {
  #[cfg(feature = "otel")]
  pub(crate) meter_provider: Option<MeterProvider>,
}

#[cfg(feature = "otel")]
impl Drop for Guard {
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
