use crate::error::*;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
/// Config toml
pub struct ConfigToml {
  /// Listen address [default: "0.0.0.0"]
  pub listen_address: Option<String>,
  /// Listen port [default: 8080]
  pub listen_port: Option<u16>,
  /// Serving hostname
  pub hostname: Option<String>,
  /// Serving path [default: "/proxy"]
  pub path: Option<String>,
  /// Maximum number of subsequence nodes [default: 3]
  pub max_subseq_nodes: Option<usize>,
  /// Authentication information. if None, no authentication.
  pub auth: Option<Auth>,
  /// Access control information. if None, no access control.
  pub access: Option<Access>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
/// Authentication of source, typically user clients, using Id token
pub struct Auth {
  /// Allowed token information
  pub token: Vec<Token>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
/// Allowed token information
pub struct Token {
  /// Token api endpoint from which jwks is automatically retrieved
  pub token_api: String,
  /// Token issuer evaluated from iss claim
  pub token_issuer: Option<String>,
  /// Allowed client ids evaluated from aud claim
  pub client_ids: Vec<String>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
/// Allowed source ip addresses and destination domains
pub struct Access {
  /// Allowed source ip addresses
  pub allowed_source_ip_addresses: Vec<String>,
  /// Allowed destination domains
  pub allowed_destination_domains: Vec<String>,
}

impl ConfigToml {
  pub(super) fn new(config_file: &str) -> anyhow::Result<Self> {
    let config_str = fs::read_to_string(config_file)?;

    toml::from_str(&config_str).map_err(|e| anyhow!(e))
  }
}
