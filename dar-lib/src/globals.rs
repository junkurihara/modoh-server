use crate::{auth::ValidationKey, constants::*};
use std::{
  net::{IpAddr, SocketAddr},
  sync::Arc,
  time::Duration,
};
use url::Url;

/// Global objects
pub struct Globals {
  /// Configuration of the relay
  pub relay_config: RelayConfig,

  /// Tokio runtime handler
  pub runtime_handle: tokio::runtime::Handle,

  /// Tokio termination notifier
  pub term_notify: Option<Arc<tokio::sync::Notify>>,
}

#[derive(Clone)]
/// Relay configuration passed from outside
pub struct RelayConfig {
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
  /// timeout for relaying operation
  pub timeout: Duration,

  /// hostname of the relay
  pub hostname: String,
  /// url path that the relay listening on
  pub path: String,
  /// maximum number of subsequence nodes
  pub max_subseq_nodes: usize,

  /// Authentication information. if None, no authentication.
  pub auth: Option<AuthConfig>,
}

#[derive(Clone)]
/// Authentication of source, typically user clients, using Id token
pub struct AuthConfig {
  /// Allowed token information
  token: Option<Vec<TokenConfig>>,
  /// Allowed source ip addresses and destination domains
  ip_and_domain: Option<IpAndDomainConfig>,
}

#[derive(Clone)]
/// Allowed token information
pub struct TokenConfig {
  /// Token issuer url
  token_issuer_url: Url,
  /// Allowed client ids
  client_ids: Vec<String>,
  /// Validation key
  validation_key: ValidationKey,
}

#[derive(Clone)]
/// Allowed source ip addresses and destination domains
pub struct IpAndDomainConfig {
  /// Allowed source ip addresses
  allowed_source_ip_addresses: Vec<IpAddr>,
  /// Allowed destination domains
  allowed_destination_domains: Vec<String>,
}

impl Default for RelayConfig {
  fn default() -> Self {
    Self {
      listener_socket: LISTEN_SOCKET.parse().unwrap(),
      tcp_listen_backlog: TCP_LISTEN_BACKLOG,
      max_clients: MAX_CLIENTS,
      max_concurrent_streams: MAX_CONCURRENT_STREAMS,
      keepalive: KEEPALIVE,
      timeout: Duration::from_secs(TIMEOUT),
      hostname: HOSTNAME.to_string(),
      path: PATH.to_string(),
      max_subseq_nodes: MODOH_MAX_SUBSEQ_NODES,
      auth: None,
    }
  }
}
