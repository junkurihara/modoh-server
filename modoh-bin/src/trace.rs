use std::str::FromStr;
#[allow(unused)]
pub use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, prelude::*};

#[cfg(feature = "otel-trace")]
use crate::otel::init_tracer;
#[cfg(feature = "otel-trace")]
use tracing_opentelemetry::OpenTelemetryLayer;

#[cfg(feature = "otel-metrics")]
use crate::otel::init_meter_provider;
#[cfg(feature = "otel-metrics")]
use opentelemetry_sdk::metrics::SdkMeterProvider;

#[cfg(feature = "qrlog")]
use crate::constants::QRLOG_EVENT_NAME;

const TOKEN_SERVER_VALIDATOR_PKG_NAME: &str = "rust-token-server-validator";

/// Initialize tracing subscriber
pub fn init_tracing_subscriber(_trace_config: &TraceConfig<String>, _qrlog_config: &QrlogConfig) -> MetricsGuard {
  let level_string = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
  let level = tracing::Level::from_str(level_string.as_str()).unwrap_or(tracing::Level::INFO);

  let passed_pkg_names = [
    env!("CARGO_PKG_NAME").replace('-', "_"),
    TOKEN_SERVER_VALIDATOR_PKG_NAME.replace('-', "_"),
  ];

  // This limits the logger to emits only this crate with any level, for included crates it will emit only INFO or above level.
  let stdio_layer = fmt::layer()
    .with_line_number(true)
    .with_thread_ids(false)
    .with_thread_names(true)
    .with_target(true)
    .with_level(true)
    .compact()
    .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
      (passed_pkg_names
        .iter()
        .any(|pkg_name| metadata.target().starts_with(pkg_name))
        && metadata.level() <= &level)
        || metadata.level() <= &tracing::Level::WARN.min(level)
    }));

  let reg = tracing_subscriber::registry().with(stdio_layer);

  // metrics
  // tracing-opentelemetry for metrics is disabled and we use opentelemetry directly for metrics.
  let metrics_guard = MetricsGuard {
    #[cfg(feature = "otel-metrics")]
    meter_provider: {
      match _trace_config.otel_config.as_ref() {
        None => None,
        Some(otel_config) => {
          if otel_config.metrics_enabled {
            println!("Opentelemetry is enabled for metrics");
            Some(init_meter_provider(otel_config))
          } else {
            None
          }
        }
      }
    },
  };

  #[cfg(feature = "otel-trace")]
  let otel_filter = tracing_subscriber::filter::filter_fn(move |metadata| {
    metadata
      .target()
      .starts_with(env!("CARGO_PKG_NAME").replace('-', "_").as_str())
      && metadata.level() <= &level
      && !metadata.name().contains(QRLOG_EVENT_NAME)
  });

  #[cfg(feature = "qrlog")]
  let qlog_layer_base = fmt::layer()
    .with_line_number(false)
    .with_thread_ids(false)
    .with_thread_names(false)
    .with_target(false)
    .with_level(false)
    .with_timer(fmt::time::ChronoLocal::new("%s".to_string()))
    .json()
    .with_span_list(false)
    .with_current_span(false);

  #[cfg(all(any(feature = "otel-trace", feature = "otel-metrics"), feature = "qrlog"))]
  {
    match (_trace_config.otel_config.as_ref(), _qrlog_config.qrlog_path.as_ref()) {
      (None, None) => {
        reg.init();
      }
      /* --------------------------------- */
      (Some(otel_config), None) => {
        // traces
        #[cfg(feature = "otel-trace")]
        if otel_config.trace_enabled {
          println!("Opentelemetry is enabled for traces");

          reg
            .with(OpenTelemetryLayer::new(init_tracer(otel_config)).with_filter(otel_filter))
            .init();
        } else {
          reg.init();
        }
        #[cfg(not(feature = "otel-trace"))]
        reg.init();
      }
      /* --------------------------------- */
      (None, Some(qrlog_path)) => {
        let qrlog_file = qrlog_file(qrlog_path);
        // Query and response logger in json format
        let reg = reg.with(qlog_layer_base.with_writer(qrlog_file).with_filter(QrlogFilter));
        println!("Query-response logging is enabled");
        reg.init();
      }
      /* --------------------------------- */
      (Some(otel_config), Some(qrlog_path)) => {
        let qrlog_file = qrlog_file(qrlog_path);
        // Query and response logger in json format
        let reg = reg.with(qlog_layer_base.with_writer(qrlog_file).with_filter(QrlogFilter));
        println!("Query-response logging is enabled");

        // traces
        #[cfg(feature = "otel-trace")]
        if otel_config.trace_enabled {
          println!("Opentelemetry is enabled for traces");
          reg
            .with(OpenTelemetryLayer::new(init_tracer(otel_config)).with_filter(otel_filter))
            .init();
        } else {
          reg.init();
        }
        #[cfg(not(feature = "otel-trace"))]
        reg.init();
      }
    }
  }
  #[cfg(all(any(feature = "otel-trace", feature = "otel-metrics"), not(feature = "qrlog")))]
  {
    if _trace_config.otel_config.is_none() {
      reg.init();
    } else {
      let otel_config = _trace_config.otel_config.as_ref().unwrap();

      // traces
      #[cfg(feature = "otel-trace")]
      if otel_config.trace_enabled {
        println!("Opentelemetry is enabled for traces");
        reg
          .with(OpenTelemetryLayer::new(init_tracer(otel_config)).with_filter(otel_filter))
          .init();
      } else {
        reg.init();
      }
      #[cfg(not(feature = "otel-trace"))]
      reg.init();
    }
  }
  #[cfg(all(feature = "qrlog", not(any(feature = "otel-trace", feature = "otel-metrics"))))]
  {
    if let Some(qrlog_path) = _qrlog_config.qrlog_path.as_ref() {
      let qrlog_file = qrlog_file(qrlog_path);
      // Query and response logger in json format
      let reg = reg.with(qlog_layer_base.with_writer(qrlog_file).with_filter(QrlogFilter));
      println!("Query-response logging is enabled");
      reg.init();
    } else {
      reg.init();
    }
  }
  #[cfg(not(any(feature = "otel-trace", feature = "otel-metrics", feature = "qrlog")))]
  {
    reg.init();
  }

  metrics_guard
}

#[cfg(feature = "qrlog")]
struct QrlogFilter;
#[cfg(feature = "qrlog")]
impl<S> tracing_subscriber::layer::Filter<S> for QrlogFilter {
  fn enabled(&self, metadata: &tracing::Metadata<'_>, _: &tracing_subscriber::layer::Context<'_, S>) -> bool {
    metadata
      .target()
      .starts_with(env!("CARGO_PKG_NAME").replace('-', "_").as_str())
      && metadata.name().contains(QRLOG_EVENT_NAME)
      && metadata.level() <= &tracing::Level::INFO
  }
}

#[cfg(feature = "qrlog")]
#[inline]
fn qrlog_file(path: &str) -> std::fs::File {
  // crate a file if it does not exist
  std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(path)
    .expect("Failed to open qrlog file")
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
  pub meter_provider: Option<SdkMeterProvider>,
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

/// Configuration for query-response logging
pub(crate) struct QrlogConfig {
  #[cfg(feature = "qrlog")]
  pub(crate) qrlog_path: Option<String>,
  pub(crate) _marker: std::marker::PhantomData<fn() -> ()>,
}
