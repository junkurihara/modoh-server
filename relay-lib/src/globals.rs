use crate::constants::*;
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

  /// Access control information. if None, no access control.
  pub access: Option<AccessConfig>,
}

#[derive(Clone)]
/// Authentication of source, typically user clients, using Id token
pub struct AuthConfig {
  /// Allowed token information
  pub inner: Vec<TokenConfigInner>,
}

#[derive(Clone)]
/// Allowed token information
pub struct TokenConfigInner {
  /// Token issuer url, validation_key is automatically retrieved from the url
  pub token_issuer_url: Url,
  /// Allowed client ids
  pub client_ids: Vec<String>,
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
      access: None,
    }
  }
}
