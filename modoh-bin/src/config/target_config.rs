use super::toml::ConfigToml;
use crate::{error::*, trace::*};
use async_trait::async_trait;
use hot_reload::{Reload, ReloaderError};
use ipnet::IpNet;
use modoh_server_lib::{AccessConfig, HttpSigConfig, HttpSigDomainInfo, ServiceConfig, ValidationConfig, ValidationConfigInner};
use std::{
  fs::read_to_string,
  net::{IpAddr, SocketAddr},
};

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
    let config_toml =
      ConfigToml::new(&self.config_path).map_err(|_e| ReloaderError::<TargetConfig>::Reload("Failed to reload config toml"))?;

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

impl TryInto<ServiceConfig> for &TargetConfig {
  type Error = anyhow::Error;

  fn try_into(self) -> Result<ServiceConfig, Self::Error> {
    let mut service_conf = ServiceConfig::default();

    if let Some(addr) = &self.config_toml.listen_address {
      let addr = addr.parse::<std::net::IpAddr>()?;
      service_conf.listener_socket.set_ip(addr);
    }
    if let Some(port) = &self.config_toml.listen_port {
      service_conf.listener_socket.set_port(*port);
    }
    info!("Listening on {}", service_conf.listener_socket);

    if let Some(hostname) = &self.config_toml.hostname {
      service_conf.hostname = hostname.clone();
    }
    info!("Hostname: {}", service_conf.hostname);

    ensure!(
      self.config_toml.relay.is_some() || self.config_toml.target.is_some(),
      "Either relay or target must be set"
    );
    if let Some(relay) = &self.config_toml.relay {
      info!("(M)ODoH relay enabled");
      if let Some(path) = &relay.path {
        service_conf.relay.as_mut().unwrap().path = path.clone();
      }
      info!("Relay path: {}", service_conf.relay.as_ref().unwrap().path);

      if let Some(max_subseq_nodes) = &relay.max_subseq_nodes {
        service_conf.relay.as_mut().unwrap().max_subseq_nodes = *max_subseq_nodes;
      }
      info!(
        "Relay max subsequence nodes: {}",
        service_conf.relay.as_ref().unwrap().max_subseq_nodes
      );
      if let Some(http_user_agent) = &relay.forwarder_user_agent {
        service_conf.relay.as_mut().unwrap().http_user_agent = http_user_agent.clone();
      }
      info!(
        "Relay http user agent: {}",
        service_conf.relay.as_ref().unwrap().http_user_agent
      );
    } else {
      service_conf.relay = None;
    }
    if let Some(target) = &self.config_toml.target {
      info!("(M)ODoH target enabled");
      if let Some(path) = &target.path {
        service_conf.target.as_mut().unwrap().path = path.clone();
      }
      info!("Target path: {}", service_conf.target.as_ref().unwrap().path);

      if let Some(upstream) = &target.upstream {
        let upstream = upstream.parse::<SocketAddr>()?;
        service_conf.target.as_mut().unwrap().upstream = upstream;
      }
      info!("Target upstream: {}", service_conf.target.as_ref().unwrap().upstream);

      if let Some(local_bind_address) = &target.local_bind_address {
        let local_bind_address = local_bind_address.parse::<SocketAddr>()?;
        service_conf.target.as_mut().unwrap().local_bind_address = local_bind_address;
      }
      info!(
        "Target local bind address: {}",
        service_conf.target.as_ref().unwrap().local_bind_address
      );

      if let Some(error_ttl) = &target.error_ttl {
        service_conf.target.as_mut().unwrap().error_ttl = *error_ttl;
      }
      info!("Target error ttl: {}", service_conf.target.as_ref().unwrap().error_ttl);
      if let Some(max_ttl) = &target.max_ttl {
        service_conf.target.as_mut().unwrap().max_ttl = *max_ttl;
      }
      info!("Target max ttl: {}", service_conf.target.as_ref().unwrap().max_ttl);
      if let Some(min_ttl) = &target.min_ttl {
        service_conf.target.as_mut().unwrap().min_ttl = *min_ttl;
      }
      info!("Target min ttl: {}", service_conf.target.as_ref().unwrap().min_ttl);
    } else {
      service_conf.target = None;
    }

    if self.config_toml.validation.is_none() {
      return Ok(service_conf);
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
      service_conf.validation = Some(ValidationConfig { inner });
    };

    if let Some(access) = self.config_toml.access.as_ref() {
      let mut inner_ip = vec![];
      for ip in access.allowed_source_ips.as_ref().unwrap_or(&vec![]).iter() {
        let ip = parse_ipnet(ip)?;
        info!("Set allowed source ip address: {}", ip);
        inner_ip.push(ip);
      }

      let mut inner_cdn_ip = vec![];
      for ip in access.trusted_cdn_ips.as_ref().unwrap_or(&vec![]).iter() {
        let ip = ip.parse::<IpNet>()?;
        info!("Set trusted cdn ip address: {}", ip);
        inner_cdn_ip.push(ip);
      }
      if let Some(cdn_ip_list_path) = access.trusted_cdn_ips_file.as_ref() {
        let ip_list = read_ipnet_list_from_file(cdn_ip_list_path)?;
        info!("Set trusted cdn ip address from file: {:#?}", ip_list);
        inner_cdn_ip.extend(ip_list);
      }

      let trust_previous_hop = access.trust_previous_hop.unwrap_or(true);
      info!("Set trust previous hop: {}", trust_previous_hop);

      let mut inner_domain = vec![];
      if service_conf.relay.is_some() {
        for domain in access.allowed_destination_domains.as_ref().unwrap_or(&vec![]).iter() {
          let domain = url::Url::parse(&format!("https://{domain}"))?
            .authority()
            .to_ascii_lowercase();
          info!("Set allowed destination domain for relaying: {}", domain);
          inner_domain.push(domain);
        }
      }

      let httpsig = if let Some(httpsig) = access.httpsig.as_ref() {
        let mut httpsig_config = HttpSigConfig::default();
        if let Some(key_types) = &httpsig.key_types {
          let key_types = key_types
            .iter()
            .map(|s| s.as_str().try_into())
            .collect::<Result<Vec<_>, _>>()?;
          httpsig_config.key_types = key_types;
        }
        info!(
          "Set available key types for HttpSig: {}",
          httpsig_config
            .key_types
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(", ")
        );
        if let Some(key_rotation_period) = &httpsig.key_rotation_period {
          httpsig_config.key_rotation_period = std::time::Duration::from_secs(*key_rotation_period);
        }
        info!(
          "Set key rotation period for HttpSig: {}",
          httpsig_config.key_rotation_period.as_secs()
        );
        if let Some(enabled_domains) = &httpsig.enabled_domains {
          let enabled_domains = enabled_domains
            .iter()
            .map(|domain| {
              HttpSigDomainInfo::new(
                domain.configs_endpoint_domain.clone(),
                domain.dh_signing_target_domain.clone(),
              )
            })
            .collect();
          httpsig_config.enabled_domains = enabled_domains;
        }
        info!("Set HttpSig-enabled targeted domains: {:#?}", httpsig_config.enabled_domains);

        if let Some(false) = httpsig.accept_previous_dh_public_keys {
          httpsig_config.previous_dh_public_keys_gen = 0;
        }
        info!(
          "Accept previous DH public keys to fill the gap of the key rotation period: {} generations",
          httpsig_config.previous_dh_public_keys_gen
        );

        if let Some(force_verification) = httpsig.force_verification {
          httpsig_config.force_verification = force_verification;
          if force_verification {
            info!("Force httpsig verification for all requests regardless of the source ip validation result");
          }
        }
        if let Some(ignore_verification_result) = httpsig.ignore_verification_result {
          httpsig_config.ignore_verification_result = ignore_verification_result;
          if ignore_verification_result {
            warn!("Ignore httpsig verification result and continue to serve the request.");
          }
        }
        if let Some(ignore_verification_result_for_allowed_source_ips) = httpsig.ignore_verification_result_for_allowed_source_ips
        {
          httpsig_config.ignore_verification_result_for_allowed_source_ips = ignore_verification_result_for_allowed_source_ips;
          if ignore_verification_result_for_allowed_source_ips {
            warn!("Ignore httpsig verification result and continue to serve the request, only if the source ip is allowed.");
          }
        }
        Some(httpsig_config)
      } else {
        None
      };

      service_conf.access = Some(AccessConfig {
        allowed_source_ip_addresses: inner_ip,
        allowed_destination_domains: inner_domain,
        trusted_cdn_ip_addresses: inner_cdn_ip,
        trust_previous_hop,
        httpsig,
      });
    };

    Ok(service_conf)
  }
}

/// parse ipnet from string
fn parse_ipnet(ip: &str) -> anyhow::Result<IpNet> {
  if ip.contains('/') {
    let ip = ip.parse::<IpNet>()?;
    return Ok(ip);
  }
  let ip = ip.parse::<IpAddr>()?;
  Ok(IpNet::from(ip))
}

/// read ipnet list from file
fn read_ipnet_list_from_file(path: &str) -> anyhow::Result<Vec<IpNet>> {
  let list_lines = read_to_string(path)?;

  let ip_list = list_lines
    .lines()
    .filter_map(|line| {
      let line_without_comment = line.trim().split('#').next().unwrap_or("").trim();
      if line_without_comment.is_empty() {
        None
      } else {
        parse_ipnet(line_without_comment).ok()
      }
    })
    .collect::<Vec<_>>();

  Ok(ip_list)
}
