use crate::{constants::*, count::RequestCount};
use auth_validator::ValidationConfig;
use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
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
  pub allowed_source_ip_addresses: Vec<IpAddr>,
  /// Allowed destination domains
  pub allowed_destination_domains: Vec<String>,
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