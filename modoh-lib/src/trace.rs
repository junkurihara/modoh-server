pub use tracing::{debug, error, info, warn};

#[cfg(feature = "metrics")]
use opentelemetry_sdk::metrics::MeterProvider;

/// Guard for opentelemetry metrics
pub struct MetricsGuard {
  #[cfg(feature = "metrics")]
  pub meter_provider: Option<MeterProvider>,
}

#[cfg(feature = "metrics")]
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
