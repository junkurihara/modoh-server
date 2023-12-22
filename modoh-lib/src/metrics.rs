use opentelemetry::{
  global,
  metrics::{Counter, MeterProvider},
};

#[derive(Debug)]
/// Opentelemetry meters, i.e., counters, gauges, histograms, etc.
pub(crate) struct Meters {
  pub(crate) test_cnt: Counter<u64>,
  pub(crate) test_cnt2: Counter<u64>,
}

impl Meters {
  /// Create new meters
  pub(crate) fn new() -> Meters {
    let meter_provider = global::meter_provider();
    let meter = meter_provider.meter("modoh-server");

    // TODO: define metrics
    let x = meter.u64_counter("test_counter").init();
    let y = meter.u64_counter("ok").init();

    Meters {
      test_cnt: x,
      test_cnt2: y,
    }
  }
}
