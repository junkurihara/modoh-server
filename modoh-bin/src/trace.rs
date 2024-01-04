#[allow(unused)]
pub use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[cfg(feature = "otel-trace")]
use crate::otel::init_tracer;
#[cfg(feature = "otel-trace")]
use tracing_opentelemetry::OpenTelemetryLayer;

#[cfg(feature = "otel-metrics")]
use crate::otel::init_meter_provider;
#[cfg(feature = "otel-metrics")]
use opentelemetry_sdk::metrics::MeterProvider;

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

  #[cfg(any(feature = "otel-trace", feature = "otel-metrics"))]
  {
    if _trace_config.otel_config.is_none() {
      reg.init();
      MetricsGuard {
        #[cfg(feature = "otel-metrics")]
        meter_provider: None,
      }
    } else {
      let otel_config = _trace_config.otel_config.as_ref().unwrap();

      // traces
      #[cfg(feature = "otel-trace")]
      if otel_config.trace_enabled {
        println!("Opentelemetry is enabled for traces");
        reg.with(OpenTelemetryLayer::new(init_tracer(otel_config))).init();
      } else {
        reg.init();
      }
      #[cfg(not(feature = "otel-trace"))]
      reg.init();

      // metrics
      // tracing-opentelemetry for metrics is disabled and we use opentelemetry directly for metrics.
      MetricsGuard {
        #[cfg(feature = "otel-metrics")]
        meter_provider: {
          if otel_config.metrics_enabled {
            println!("Opentelemetry is enabled for metrics");
            Some(init_meter_provider(otel_config))
          } else {
            None
          }
        },
      }
    }
  }
  #[cfg(not(any(feature = "otel-trace", feature = "otel-metrics")))]
  {
    reg.init();
    MetricsGuard {}
  }
}

/// Tracing config
pub(crate) struct TraceConfig<T> {
  #[cfg(any(feature = "otel-trace", feature = "otel-metrics"))]
  pub(crate) otel_config: Option<OtelConfig<T>>,
  pub(crate) _marker: std::marker::PhantomData<fn() -> T>,
}

#[cfg(any(feature = "otel-trace", feature = "otel-metrics"))]
/// Observability config
pub(crate) struct OtelConfig<T> {
  pub(crate) otlp_endpoint: T,
  #[cfg(feature = "otel-trace")]
  pub(crate) trace_enabled: bool,
  #[cfg(feature = "otel-metrics")]
  pub(crate) metrics_enabled: bool,
  #[cfg(feature = "otel-instance-id")]
  pub(crate) service_instance_id: T,
}

/// Guard for opentelemetry metrics
pub struct MetricsGuard {
  #[cfg(feature = "otel-metrics")]
  pub meter_provider: Option<MeterProvider>,
}

#[cfg(feature = "otel-metrics")]
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
