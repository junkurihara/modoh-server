use std::net::{SocketAddr, IpAddr};
use crate::{constants::*, auth::ValidationKey};
use url::Url;


/// Global objects
pub struct Globals {
  /// Configuration of the relay
  pub relay_config: RelayConfig,
}

/// Relay configuration passed from outside
pub struct RelayConfig {
  /// Address to listen on
  pub listener_socket: SocketAddr,
  /// hostname of the relay
  pub hostname: String,
  /// url path that the relay listening on
  pub path: String,
  /// Authentication information. if None, no authentication.
  pub auth: Option<AuthConfig>,
}

/// Authentication of source, typically user clients, using Id token
pub struct AuthConfig {
  /// Allowed token information
  token: Option<Vec<TokenConfig>>,
  /// Allowed source ip addresses and destination domains
  ip_and_domain: Option<IpAndDomainConfig>,
}

/// Allowed token information
pub struct TokenConfig {
  /// Token issuer url
  token_issuer_url: Url,
  /// Allowed client ids
  client_ids: Vec<String>,
  /// Validation key
  validation_key: ValidationKey,
}

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
      listener_socket:  LISTEN_SOCKET.parse().unwrap(),
      hostname: HOSTNAME.to_string(),
      path: PATH.to_string(),
      auth: None,
    }
  }
}
