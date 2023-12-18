use opentelemetry_sdk::metrics::MeterProvider;
pub use tracing::{debug, error, info, warn};

#[cfg(feature = "otel")]
use crate::otel::{init_meter_provider, init_tracer};
#[cfg(feature = "otel")]
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
#[cfg(feature = "otel")]
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize tracing subscriber
pub fn init_tracing_subscriber() -> Guard {
  let format_layer = fmt::layer()
    .with_line_number(false)
    .with_thread_ids(false)
    .with_thread_names(true)
    .with_target(true)
    .with_level(true)
    .compact();

  // This limits the logger to emits only proxy crate
  let pkg_name = env!("CARGO_PKG_NAME").replace('-', "_");
  let level_string = std::env::var(EnvFilter::DEFAULT_ENV).unwrap_or_else(|_| "info".to_string());
  let filter_layer = EnvFilter::new(format!("{}={}", pkg_name, level_string));
  // let filter_layer = EnvFilter::try_from_default_env()
  // .unwrap_or_else(|_| EnvFilter::new("info"))
  // .add_directive(format!("{}=trace", pkg_name).parse().unwrap());

  let reg = tracing_subscriber::registry().with(format_layer).with(filter_layer);

  #[cfg(feature = "otel")]
  {
    let meter_provider = init_meter_provider();
    reg
      .with(MetricsLayer::new(meter_provider.clone()))
      .with(OpenTelemetryLayer::new(init_tracer()))
      .init();
    Guard { meter_provider }
  }
  #[cfg(not(feature = "otel"))]
  {
    reg.init();
    Guard {}
  }
}

pub(crate) struct Guard {
  #[cfg(feature = "otel")]
  pub(crate) meter_provider: MeterProvider,
}

#[cfg(feature = "otel")]
impl Drop for Guard {
  fn drop(&mut self) {
    if let Err(err) = self.meter_provider.shutdown() {
      eprintln!("{err:?}");
    }
    opentelemetry::global::shutdown_tracer_provider();
  }
}
