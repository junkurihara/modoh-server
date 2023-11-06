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
  /// Authentication information. if None, no authentication.
  pub auth: Option<Auth>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
/// Authentication of source, typically user clients, using Id token
pub struct Auth {
  /// Allowed token information
  pub token: Option<Vec<Token>>,
  /// Allowed source ip addresses and destination domains
  pub ip_and_domain: Option<IpAndDomain>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
/// Allowed token information
pub struct Token {
  /// Token issuer url
  pub token_issuer_url: String,
  /// Allowed client ids
  pub client_ids: Vec<String>,
  /// Validation key path
  pub validation_key_path: String,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct IpAndDomain {
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
