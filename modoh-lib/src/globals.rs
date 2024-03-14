use crate::{constants::*, count::RequestCount};
use auth_validator::ValidationConfig;
use httpsig_proto::HttpSigKeyTypes;
use ipnet::IpNet;
use std::{
  net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
  sync::Arc,
  time::Duration,
};

/// Global objects
pub struct Globals {
  /// Configuration of the MODoH service
  pub service_config: ServiceConfig,

  /// Tokio runtime handler
  pub runtime_handle: tokio::runtime::Handle,

  /// Tokio termination notifier
  pub term_notify: Option<Arc<tokio::sync::Notify>>,

  /// Request count, i.e., TCP sessions
  pub request_count: RequestCount,

  #[cfg(feature = "metrics")]
  /// Metrics
  pub meters: Arc<crate::metrics::Meters>,
}

#[derive(Clone)]
/// Service configuration passed from outside
pub struct ServiceConfig {
  /// Address to listen on
  pub listener_socket: SocketAddr,

  /// TCP listen backlog
  pub tcp_listen_backlog: u32,

  /// Maximum number of concurrent connections
  pub max_clients: usize,
  /// Maximum number of concurrent streams
  pub max_concurrent_streams: u32,
  /// http keepalive
  pub keepalive: bool,
  /// timeout for serving request
  pub timeout: Duration,

  /// hostname of the relay and target
  pub hostname: String,

  /// relay config
  pub relay: Option<RelayConfig>,

  /// target config
  pub target: Option<TargetConfig>,

  /// Validation information. if None, no validation using id token.
  pub validation: Option<ValidationConfig>,

  /// Access control information. if None, no access control.
  pub access: Option<AccessConfig>,
}

#[derive(Clone)]
/// Relay configuration
pub struct RelayConfig {
  /// url path that the relay listening on
  pub path: String,
  /// maximum number of subsequence nodes
  pub max_subseq_nodes: usize,
  /// http user agent
  pub http_user_agent: String,
}
#[derive(Clone)]
/// Target configuration
pub struct TargetConfig {
  /// url path that the target listening on
  pub path: String,
  /// upstream dns server address
  pub upstream: SocketAddr,
  /// local bind address to listen udp packet
  pub local_bind_address: SocketAddr,
  // TTL for errors, in seconds
  pub error_ttl: u32,
  // Maximum TTL, in seconds
  pub max_ttl: u32,
  // Minimum TTL, in seconds
  pub min_ttl: u32,
}

#[derive(Clone)]
/// Access control of source ips and target domains
/// Allowed source ip addresses and destination domains
pub struct AccessConfig {
  /// Allowed source ip addresses
  pub allowed_source_ip_addresses: Vec<IpNet>,
  /// Allowed destination domains
  pub allowed_destination_domains: Vec<String>,
  /// Trusted CDN ip addresses
  pub trusted_cdn_ip_addresses: Vec<IpNet>,
  /// Whether to trust previous hop reverse proxy
  pub trust_previous_hop: bool,
  /// Httpsig configuration
  pub httpsig: Option<HttpSigConfig>,
}

#[derive(Clone)]
/// Configuration for HTTP message signatures, which is used to
/// - verify if the incoming request is from one of the httpsig-enabled domains,
/// - sign outgoing (relayed) requests when the next node is one of the httpsig-enabled domains.
/// Note that Source IP address is prioritized over the signature verification.
/// When the destination domain is not in the list, it is not signed and dispatched without signature.
pub struct HttpSigConfig {
  /// Public key types exposed at the `httpsigconfigs` endpoint.
  /// - Public key, KEM and KDF types used for Diffie-Hellman key exchange for httpsig's hmac-sha256 signature.
  /// - Public key types used for direct signature verification.
  pub key_types: Vec<HttpSigKeyTypes>,
  /// Public key rotation period for Diffie-Hellman key exchange, in seconds.
  pub key_rotation_period: Duration,
  /// List of HTTP message signatures enabled domains, which expose public keys
  pub enabled_domains: Vec<HttpSigDomainInfo>,

  /// Refetch period for public keys
  pub refetch_period: Duration,

  /// Generations of previous dh public keys accepted to fill the gap of the key rotation period.
  pub previous_dh_public_keys_gen: usize,
  /// Number of generations of past keys generating signatures simultaneously with the current key.
  pub generation_transition_margin: usize,
  /// Force httpsig verification for all requests regardless of the source ip validation result.
  pub force_verification: bool,
  /// Ignore httpsig verification result and continue to serve the request. Useful for debugging.
  pub ignore_verification_result: bool,
  /// Ignore httpsig verification result and continue to serve the request, only if the source ip is allowed.
  pub ignore_verification_result_for_allowed_source_ips: bool,
}

impl Default for HttpSigConfig {
  fn default() -> Self {
    Self {
      key_types: vec![HttpSigKeyTypes::default()],
      key_rotation_period: Duration::from_secs(HTTPSIG_KEY_ROTATION_PERIOD),
      enabled_domains: vec![],
      refetch_period: Duration::from_secs(HTTPSIG_KEY_REFETCH_PERIOD),
      previous_dh_public_keys_gen: HTTPSIG_KEYS_STORE_PREVIOUS_COUNT,
      generation_transition_margin: HTTPSIG_KEYS_TRANSITION_MARGIN.min(HTTPSIG_KEYS_STORE_PREVIOUS_COUNT),
      force_verification: false,
      ignore_verification_result: false,
      ignore_verification_result_for_allowed_source_ips: true,
    }
  }
}

#[derive(Clone, Debug)]
/// HTTP message signatures enabled domain information
pub struct HttpSigDomainInfo {
  /// Configs endpoint
  pub configs_endpoint_uri: http::Uri,
  /// Domain name
  pub dh_signing_target_domain: String,
}

impl HttpSigDomainInfo {
  /// Create a new HttpSigDomainInfo
  pub fn new(configs_endpoint_domain: String, dh_signing_target_domain: Option<String>) -> Self {
    let configs_endpoint_uri: http::Uri = format!("https://{}{}", configs_endpoint_domain, HTTPSIG_CONFIGS_PATH)
      .parse()
      .unwrap();
    let dh_signing_target_domain =
      dh_signing_target_domain.unwrap_or_else(|| configs_endpoint_uri.authority().unwrap().to_string());
    Self {
      configs_endpoint_uri,
      dh_signing_target_domain,
    }
  }
}

impl Default for ServiceConfig {
  fn default() -> Self {
    let relay = Some(RelayConfig {
      path: RELAY_PATH.to_string(),
      max_subseq_nodes: MODOH_MAX_SUBSEQ_NODES,
      http_user_agent: format!("{}/{}", FORWARDER_USER_AGENT, env!("CARGO_PKG_VERSION")),
    });
    let upstream = UPSTREAM.parse().unwrap();
    let local_bind_address = match &upstream {
      SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
      SocketAddr::V6(s) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, s.flowinfo(), s.scope_id())),
    };
    let target = Some(TargetConfig {
      path: TARGET_PATH.to_string(),
      upstream,
      local_bind_address,
      error_ttl: ERROR_TTL,
      max_ttl: MAX_TTL,
      min_ttl: MIN_TTL,
    });
    Self {
      listener_socket: LISTEN_SOCKET.parse().unwrap(),
      tcp_listen_backlog: TCP_LISTEN_BACKLOG,
      max_clients: MAX_CLIENTS,
      max_concurrent_streams: MAX_CONCURRENT_STREAMS,
      keepalive: KEEPALIVE,
      timeout: Duration::from_secs(TIMEOUT),
      hostname: HOSTNAME.to_string(),
      relay,
      target,
      validation: None,
      access: None,
    }
  }
}
