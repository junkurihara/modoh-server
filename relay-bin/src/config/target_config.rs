use super::toml::ConfigToml;
use crate::log::*;
use async_trait::async_trait;
use doh_auth_relay_lib::{AccessConfig, RelayConfig, ValidationConfig, ValidationConfigInner};
use hot_reload::{Reload, ReloaderError};
use std::net::IpAddr;

#[derive(PartialEq, Eq, Clone, Debug)]
/// Wrapper of config toml and manipulation plugin settings
pub struct TargetConfig {
  /// config toml
  pub config_toml: ConfigToml,
}

#[derive(Clone)]
/// config toml reloader
pub struct ConfigReloader {
  pub config_path: String,
}

#[async_trait]
impl Reload<TargetConfig> for ConfigReloader {
  type Source = String;
  async fn new(source: &Self::Source) -> Result<Self, ReloaderError<TargetConfig>> {
    Ok(Self {
      config_path: source.clone(),
    })
  }

  async fn reload(&self) -> Result<Option<TargetConfig>, ReloaderError<TargetConfig>> {
    let config_toml = ConfigToml::new(&self.config_path)
      .map_err(|_e| ReloaderError::<TargetConfig>::Reload("Failed to reload config toml"))?;

    Ok(Some(TargetConfig { config_toml }))
  }
}

impl TargetConfig {
  /// build new target config by loading query manipulation plugin configs
  pub async fn new(config_file: &str) -> anyhow::Result<Self> {
    let config_toml = ConfigToml::new(config_file)?;
    Ok(Self { config_toml })
  }
}

impl TryInto<RelayConfig> for &TargetConfig {
  type Error = anyhow::Error;

  fn try_into(self) -> Result<RelayConfig, Self::Error> {
    let mut relay_conf = RelayConfig::default();

    if let Some(addr) = &self.config_toml.listen_address {
      let addr = addr.parse::<std::net::IpAddr>()?;
      relay_conf.listener_socket.set_ip(addr);
    }
    if let Some(port) = &self.config_toml.listen_port {
      relay_conf.listener_socket.set_port(*port);
    }
    info!("Listening on {}", relay_conf.listener_socket);

    if let Some(hostname) = &self.config_toml.hostname {
      relay_conf.hostname = hostname.clone();
    }
    info!("Hostname: {}", relay_conf.hostname);

    if let Some(path) = &self.config_toml.path {
      relay_conf.path = path.clone();
    }
    info!("Path: {}", relay_conf.path);
    if let Some(max_subseq_nodes) = &self.config_toml.max_subseq_nodes {
      relay_conf.max_subseq_nodes = *max_subseq_nodes;
    }
    info!("Max subsequence nodes: {}", relay_conf.max_subseq_nodes);
    if let Some(http_user_agent) = &self.config_toml.forwarder_user_agent {
      relay_conf.http_user_agent = http_user_agent.clone();
    }
    info!("Http user agent: {}", relay_conf.http_user_agent);

    if self.config_toml.validation.is_none() {
      return Ok(relay_conf);
    }

    if let Some(validation) = self.config_toml.validation.as_ref() {
      let mut inner = vec![];
      for token in validation.token.iter() {
        let token_api = token.token_api.parse()?;
        let token_issuer = token.token_issuer.clone().unwrap_or(token.token_api.clone()).parse()?;
        let t = ValidationConfigInner {
          token_api,
          token_issuer,
          client_ids: token.client_ids.clone(),
        };
        info!(
          "Set ID token validation: endpoing {}, iss {}, aud {:?}",
          t.token_api, t.token_issuer, t.client_ids
        );
        inner.push(t);
      }
      relay_conf.validation = Some(ValidationConfig { inner });
    };

    if let Some(access) = self.config_toml.access.as_ref() {
      let mut inner_ip = vec![];
      for ip in access.allowed_source_ip_addresses.iter() {
        let ip = ip.parse::<IpAddr>()?;
        info!("Set allowed source ip address: {}", ip);
        inner_ip.push(ip);
      }

      let mut inner_domain = vec![];
      for domain in access.allowed_destination_domains.iter() {
        let domain = url::Url::parse(&format!("https://{domain}"))?
          .authority()
          .to_ascii_lowercase();
        info!("Set allowed destination domain: {}", domain);
        inner_domain.push(domain);
      }

      relay_conf.access = Some(AccessConfig {
        allowed_source_ip_addresses: inner_ip,
        allowed_destination_domains: inner_domain,
      });
    };

    Ok(relay_conf)
  }
}
