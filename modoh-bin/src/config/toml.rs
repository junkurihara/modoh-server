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
  /// Target settings
  pub target: Option<Target>,
  /// Relay settings
  pub relay: Option<Relay>,
  /// Validation information. if None, no validation using id token.
  pub validation: Option<Validation>,
  /// Access control information. if None, no access control.
  pub access: Option<Access>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
/// Target settings
pub struct Target {
  /// Serving path [default: "/dns-query"]
  pub path: Option<String>,
  /// Upstream dns server address [default: "8.8.8.8:53"]
  pub upstream: Option<String>,
  /// Local bind address to listen udp packet
  pub local_bind_address: Option<String>,
  // TTL for errors, in seconds
  pub error_ttl: Option<u32>,
  // Maximum TTL, in seconds
  pub max_ttl: Option<u32>,
  // Minimum TTL, in seconds
  pub min_ttl: Option<u32>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
/// Relay settings
pub struct Relay {
  /// Serving path [default: "/proxy"]
  pub path: Option<String>,
  /// Maximum number of subsequence nodes [default: 3]
  pub max_subseq_nodes: Option<usize>,
  /// Forwarder http user agent [default: "modoh-server/<VERSION>"]
  pub forwarder_user_agent: Option<String>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
/// Validation of source, typically user clients, using Id token
pub struct Validation {
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
  pub allowed_source_ips: Option<Vec<String>>,

  /// Trusted cdn ip addresses
  pub trusted_cdn_ips: Option<Vec<String>>,
  /// Trusted cdn ip addresses file
  pub trusted_cdn_ips_file: Option<String>,
  /// Always trust previous proxy address retrieved from remote_addr
  pub trust_previous_hop: Option<bool>,

  /// Allowed destination domains
  pub allowed_destination_domains: Option<Vec<String>>,

  /// Configuration for HTTP message signatures
  pub httpsig: Option<HttpSig>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
/// Configuration for HTTP message signatures
pub struct HttpSig {
  /// Public key types exposed at the `httpsigconfigs` endpoint.
  /// - Public key, KEM and KDF types used for Diffie-Hellman key exchange for httpsig's hmac-sha256 signature.
  /// - Public key types used for direct signature verification.
  pub key_types: Option<Vec<String>>,
  /// Public key rotation period in seconds.
  pub key_rotation_period: Option<u64>,
  /// List of HTTP message signatures enabled domains, which exposes public keys for Diffie-Hellman key exchange or directly for signature verification.
  pub enabled_domains: Option<Vec<HttpSigEnabledDomains>>,
  /// Accept previous DH public keys to fill the gap of the key rotation period.
  pub accept_previous_dh_public_keys: Option<bool>,
  /// Force httpsig verification for all requests regardless of the source ip validation result.
  pub force_verification: Option<bool>,
  /// Ignore the result of httpsig verification (verification itself is performed), and continue to serve the request.
  pub ignore_verification_result: Option<bool>,
  /// Ignore the result of httpsig verification (verification itself is performed), and continue to serve the request, only if the source ip is allowed.
  pub ignore_verification_result_for_allowed_source_ips: Option<bool>,
}

#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
/// Object with configs_endpoint_domain and dh_signing_target_domain
pub struct HttpSigEnabledDomains {
  /// Configs endpoint domain
  pub configs_endpoint_domain: String,
  /// DH signing target domain
  pub dh_signing_target_domain: Option<String>,
}

impl ConfigToml {
  pub(super) fn new(config_file: &str) -> anyhow::Result<Self> {
    let config_str = fs::read_to_string(config_file)?;

    toml::from_str(&config_str).map_err(|e| anyhow!(e))
  }
}
