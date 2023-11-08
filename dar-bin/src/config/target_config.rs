use super::toml::ConfigToml;
use crate::{constants::*, error::*, log::*};
use async_trait::async_trait;
use doh_auth_relay_lib::{AuthConfig, IpAndDomainConfig, RelayConfig, TokenConfig};
use hot_reload::{Reload, ReloaderError};
use std::{env, sync::Arc};
use tokio::time::Duration;

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

    if self.config_toml.auth.is_none() {
      return Ok(relay_conf);
    }

    let auth = self.config_toml.auth.as_ref().unwrap();

    Ok(relay_conf)
  }
}
