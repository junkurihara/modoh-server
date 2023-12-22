pub const CONFIG_WATCH_DELAY_SECS: u32 = 30;
#[cfg(feature = "otel")]
pub const DEFAULT_OTLP_ENDPOINT: &str = "http://localhost:4317";
#[cfg(feature = "otel")]
pub const OTEL_SERVICE_NAMESPACE: &str = "modoh";
