pub use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[cfg(feature = "otel")]
use crate::otel::{init_meter_provider, init_tracer};
#[cfg(feature = "otel")]
use opentelemetry_sdk::metrics::MeterProvider;
#[cfg(feature = "otel")]
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};

/// Initialize tracing subscriber
pub fn init_tracing_subscriber<'a, T>(trace_config: &'a TraceConfig<T>) -> Guard
where
  T: Into<String> + 'a,
  std::string::String: std::convert::From<&'a T>,
{
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
    if trace_config.otlp_endpoint.is_none() {
      reg.init();
      Guard { meter_provider: None }
    } else {
      println!("Opentelemetry is enabled");
      let otlp_endpoint = trace_config.otlp_endpoint.as_ref().unwrap();
      let meter_provider = init_meter_provider(otlp_endpoint);
      reg
        .with(MetricsLayer::new(meter_provider.clone()))
        .with(OpenTelemetryLayer::new(init_tracer(otlp_endpoint)))
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
pub(crate) struct TraceConfig<T>
where
  T: Into<String>,
{
  #[cfg(feature = "otel")]
  pub(crate) otlp_endpoint: Option<T>,
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
