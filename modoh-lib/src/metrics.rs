use opentelemetry::{
  global,
  metrics::{Counter, MeterProvider},
};

#[derive(Debug)]
/// Opentelemetry meters, i.e., counters, gauges, histograms, etc.
pub(crate) struct Meters {
  /// counter for token validation
  pub(crate) token_validation: Counter<u64>,
  /// counter for token validation error
  pub(crate) token_validation_error: Counter<u64>,
}

impl Meters {
  /// Create new meters
  pub(crate) fn new() -> Meters {
    let meter_provider = global::meter_provider();
    let meter = meter_provider.meter("modoh-server");

    // define metrics and change monotonic_counter to metrics defined here
    let token_validation = meter
      .u64_counter("token_validation")
      .with_description("Count of token validation")
      .init();
    let token_validation_error = meter
      .u64_counter("token_validation_error")
      .with_description("Count of token validation error")
      .init();
    // TODO: define more

    Meters {
      token_validation,
      token_validation_error,
    }
  }
}
