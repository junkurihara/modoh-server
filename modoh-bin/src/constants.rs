pub const CONFIG_WATCH_DELAY_SECS: u32 = 30;
#[cfg(any(feature = "otel-trace", feature = "otel-metrics"))]
pub const DEFAULT_OTLP_ENDPOINT: &str = "http://localhost:4317";
#[cfg(any(feature = "otel-trace", feature = "otel-metrics"))]
pub const OTEL_SERVICE_NAMESPACE: &str = "modoh";
#[cfg(feature = "otel-trace")]
pub const OTEL_TRACE_BATCH_QUEUE_SIZE: usize = 8192;

#[cfg(feature = "qrlog")]
pub const QRLOG_EVENT_NAME: &str = "qrlog";
