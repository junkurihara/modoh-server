use opentelemetry::{
  global,
  metrics::{Counter, Histogram, MeterProvider, Unit},
};

#[derive(Debug)]
/// Opentelemetry meters, i.e., counters, gauges, histograms, etc.
pub(crate) struct Meters {
  /// counter for token validation
  pub(crate) token_validation: Counter<u64>,
  /// counter for token validation error
  pub(crate) token_validation_result_error: Counter<u64>,
  /// counter for query odoh_configs
  pub(crate) query_odoh_configs: Counter<u64>,
  /// counter for query odoh_configs error
  pub(crate) query_odoh_configs_result_error: Counter<u64>,
  /// counter for query httpsig_configs
  pub(crate) query_httpsig_configs: Counter<u64>,
  /// counter for query httpsig_configs error
  pub(crate) query_httpsig_configs_result_error: Counter<u64>,
  /// counter for source ip access control execution
  pub(crate) src_ip_access_control: Counter<u64>,
  /// counter for rejection by source ip access control
  pub(crate) src_ip_access_control_result_rejected: Counter<u64>,
  /// counter for httpsig verification
  pub(crate) httpsig_verification: Counter<u64>,
  /// counter for httpsig verification error
  pub(crate) httpsig_verification_rejected: Counter<u64>,
  /// counter for anonymized/relaying query
  pub(crate) query_relaying: Counter<u64>,
  /// counter for token-validated anonymized/relaying query
  pub(crate) query_token_validated_relaying: Counter<u64>,
  /// counter for responded anonymized/relaying query
  pub(crate) query_relaying_result_responded: Counter<u64>,
  /// counter for anonymized/relaying query error
  pub(crate) query_relaying_result_error: Counter<u64>,
  /// counter for query as target
  pub(crate) query_target: Counter<u64>,
  /// counter for token-validated targeted query
  pub(crate) query_token_validated_target: Counter<u64>,
  /// counter for responded targeted query
  pub(crate) query_target_result_responded: Counter<u64>,
  /// counter for targeted query error
  pub(crate) query_target_result_error: Counter<u64>,

  /// counter for DoH query via GET as target
  pub(crate) query_target_doh_get: Counter<u64>,
  /// counter for DoH query via POST as target
  pub(crate) query_target_doh_post: Counter<u64>,
  /// counter for (M)ODoH query as target
  pub(crate) query_target_modoh: Counter<u64>,
  /// counter for upstream raw DNS server error
  pub(crate) upstream_raw_dns_server_error: Counter<u64>,
  /// counter for upstream query tcp (fallback from udp)
  pub(crate) upstream_query_tcp: Counter<u64>,
  /// histogram for target upstream latency
  pub(crate) latency_target_upstream: Histogram<u64>,

  /// histogram for subsequent relay number
  pub(crate) subsequent_relay_num: Histogram<u64>,
  /// histogram for relaying upstream latency
  pub(crate) latency_relay_upstream: Histogram<u64>,
  /// counter for destination domain access control
  pub(crate) dst_domain_access_control: Counter<u64>,
  /// counter for rejection by destination domain access control
  pub(crate) dst_domain_access_control_result_rejected: Counter<u64>,
}

impl Meters {
  /// Create new meters
  pub(crate) fn new() -> Meters {
    let meter_provider = global::meter_provider();
    let meter = meter_provider.meter("modoh-server");

    // define metrics
    let token_validation = meter
      .u64_counter("token_validation")
      .with_description("Count of token validation")
      .init();
    let token_validation_result_error = meter
      .u64_counter("token_validation_result_error")
      .with_description("Count of failure result of token validation")
      .init();
    let query_odoh_configs = meter
      .u64_counter("query_odoh_configs")
      .with_description("Count of queries for odoh_configs")
      .init();
    let query_odoh_configs_result_error = meter
      .u64_counter("query_odoh_configs_result_error")
      .with_description("Count of queries for odoh_configs error")
      .init();

    let query_httpsig_configs = meter
      .u64_counter("query_httpsig_configs")
      .with_description("Count of queries for httpsig_configs")
      .init();
    let query_httpsig_configs_result_error = meter
      .u64_counter("query_httpsig_configs_result_error")
      .with_description("Count of queries for httpsig_configs error")
      .init();

    let src_ip_access_control = meter
      .u64_counter("src_ip_access_control")
      .with_description("Count of source ip access control execution")
      .init();
    let src_ip_access_control_result_rejected = meter
      .u64_counter("src_ip_access_control_result_rejected")
      .with_description("Count of rejection by source ip access control")
      .init();

    let httpsig_verification = meter
      .u64_counter("httpsig_verification")
      .with_description("Count of httpsig verification")
      .init();
    let httpsig_verification_rejected = meter
      .u64_counter("httpsig_verification_rejected")
      .with_description("Count of rejection by httpsig verification")
      .init();

    let query_relaying = meter
      .u64_counter("query_relaying")
      .with_description("Count of anonymized/relaying query")
      .init();
    let query_token_validated_relaying = meter
      .u64_counter("query_token_validated_relaying")
      .with_description("Count of token-validated anonymized/relaying query")
      .init();
    let query_relaying_result_responded = meter
      .u64_counter("query_relaying_result_responded")
      .with_description("Count of responded result by the upstream servers for anonymized/relaying query")
      .init();
    let query_relaying_result_error = meter
      .u64_counter("query_relaying_result_error")
      .with_description("Count of failure result for relaying anonymized/relaying query")
      .init();
    let query_target = meter
      .u64_counter("query_target")
      .with_description("Count of query as target")
      .init();
    let query_token_validated_target = meter
      .u64_counter("query_token_validated_target")
      .with_description("Count of token-validated targeted query")
      .init();
    let query_target_result_responded = meter
      .u64_counter("query_target_result_responded")
      .with_description("Count of responded result by the upstream DNS servers for targeted query")
      .init();
    let query_target_result_error = meter
      .u64_counter("query_target_result_error")
      .with_description("Count of failure result for targeted query")
      .init();

    let query_target_doh_get = meter
      .u64_counter("query_target_doh_get")
      .with_description("Count of DoH query via GET as target")
      .init();
    let query_target_doh_post = meter
      .u64_counter("query_target_doh_post")
      .with_description("Count of DoH query via POST as target")
      .init();
    let query_target_modoh = meter
      .u64_counter("query_target_modoh")
      .with_description("Count of (M)ODoH query as target")
      .init();
    let upstream_raw_dns_server_error = meter
      .u64_counter("upstream_raw_dns_server_error")
      .with_description("Count of upstream raw DNS server error")
      .init();
    let upstream_query_tcp = meter
      .u64_counter("upstream_query_tcp")
      .with_description("Count of upstream query via TCP due to the truncation of UDP packet")
      .init();
    let latency_target_upstream = meter
      .u64_histogram("latency_target_upstream")
      .with_description("Histogram of target upstream latency (msec)")
      .with_unit(Unit::new("msec"))
      .init();
    let subsequent_relay_num = meter
      .u64_histogram("subsequent_relay_num")
      .with_description("Histogram of subsequent relay number")
      .init();
    let dst_domain_access_control = meter
      .u64_counter("dst_domain_access_control")
      .with_description("Count of destination domain access control")
      .init();
    let dst_domain_access_control_result_rejected = meter
      .u64_counter("dst_domain_access_control_result_rejected")
      .with_description("Count of rejection by destination domain access control")
      .init();
    let latency_relay_upstream = meter
      .u64_histogram("latency_relay_upstream")
      .with_description("Histogram of relaying upstream latency (msec)")
      .with_unit(Unit::new("msec"))
      .init();
    // TODO: define more

    Meters {
      token_validation,
      token_validation_result_error,

      query_odoh_configs,
      query_odoh_configs_result_error,

      query_httpsig_configs,
      query_httpsig_configs_result_error,

      src_ip_access_control,
      src_ip_access_control_result_rejected,

      httpsig_verification,
      httpsig_verification_rejected,

      query_relaying,
      query_token_validated_relaying,
      query_relaying_result_responded,
      query_relaying_result_error,

      query_target,
      query_token_validated_target,
      query_target_result_responded,
      query_target_result_error,

      query_target_doh_get,
      query_target_doh_post,
      query_target_modoh,
      upstream_raw_dns_server_error,
      upstream_query_tcp,
      latency_target_upstream,

      subsequent_relay_num,
      dst_domain_access_control,
      dst_domain_access_control_result_rejected,
      latency_relay_upstream,
    }
  }
}
