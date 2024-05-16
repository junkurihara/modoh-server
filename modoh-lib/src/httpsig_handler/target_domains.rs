use crate::{
  error::*,
  globals::{HttpSigConfig, HttpSigDomain, HttpSigRegistry},
  trace::*,
};
use httpsig_registry::HttpSigDomainInfo;
use indexmap::IndexMap;
use tokio::sync::RwLock;

/// Target domains info for fetching public keys
pub(super) struct TargetDomains {
  /// Domains info given by merging local domains info and that fetched from the registry
  pub(super) inner: RwLock<Vec<HttpSigDomainInfo>>,
  /// Local domains info given from the configuration toml
  local: Vec<HttpSigDomain>,
  /// Registry list of domains info
  registry: Vec<HttpSigRegistry>,
  /// My host that is excluded as config endpoint
  my_host_name: String,
}

impl TargetDomains {
  /// Create a new TargetDomains instance with initially fetched domains info
  /// `my_host_excluded_config_endpoint` is the domain name of the host where the service is running,
  /// which should be excluded from the fetched domains info. (Unable to fetch the public key of the host itself)
  pub(super) async fn try_new(httpsig_config: &HttpSigConfig, my_host_excluded_config_endpoint: &str) -> Result<Self> {
    let local = httpsig_config.enabled_domains.clone();
    let registry = httpsig_config.enabled_domains_registry.clone();
    let my_host_name = my_host_excluded_config_endpoint.to_string();
    let inner = RwLock::new(vec![]);
    let self_ = Self {
      inner,
      local,
      registry,
      my_host_name,
    };
    self_.update().await?;
    Ok(self_)
  }
  /// Update the inner domains info by fetching from the registry and merging it with the local domains info
  pub(super) async fn update(&self) -> Result<()> {
    // from configuration file
    let mut inner_map = self
      .local
      .iter()
      .map(|v| {
        let info = HttpSigDomainInfo::new(v.configs_endpoint_domain.as_str(), v.dh_signing_target_domain.clone());
        (v.configs_endpoint_domain.clone(), info)
      })
      .collect::<IndexMap<_, _>>();

    // from registry
    let fetch_futs = self.registry.iter().map(|v| async {
      let fetched = HttpSigDomainInfo::new_from_registry_md(v.md_url.as_str(), v.public_key.as_str()).await;
      if let Err(e) = &fetched {
        error!("Failed to fetch domain info from registry: {} {e}", v.md_url);
      }
      fetched
    });
    let fetched = futures::future::join_all(fetch_futs)
      .await
      .into_iter()
      .filter_map(|v| v.ok())
      .flatten()
      .map(|v| {
        let configs_endpoint_domain = v
          .configs_endpoint_uri
          .clone()
          .authority()
          .map(|v| v.to_string())
          .unwrap_or_default();
        (configs_endpoint_domain, v)
      })
      .collect::<IndexMap<_, _>>();

    // merge and exclude my_host
    inner_map.extend(fetched);
    inner_map.swap_remove(&self.my_host_name);

    *self.inner.write().await = inner_map.into_iter().map(|(_, v)| v).collect();
    Ok(())
  }
  /// Get cloned iterator for inner
  pub(super) async fn get_all(&self) -> Vec<HttpSigDomainInfo> {
    let lock = self.inner.read().await;
    lock.iter().cloned().collect::<Vec<_>>()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_target_domains() {
    let httpsig_config = HttpSigConfig {
      enabled_domains: vec![
        HttpSigDomain {
          configs_endpoint_domain: "example.com".to_string(),
          dh_signing_target_domain: Some("example.com".to_string()),
        },
        HttpSigDomain {
          configs_endpoint_domain: "modoh03.typeq.org".to_string(),
          dh_signing_target_domain: Some("modoh03.typeq.org".to_string()),
        },
      ],
      enabled_domains_registry: vec![HttpSigRegistry {
        md_url: "https://filedn.com/lVEKDQEKcCIhnH516GYdXu0/modoh_httpsig_dev/httpsig-endpoints.md"
          .to_string()
          .parse()
          .unwrap(),
        public_key: "RWQm8wdk0lJP8AyGtShi96d72ZzkZnGX9gxR0F5EIWmMW2N25SDfzbrt".to_string(),
      }],
      ..Default::default()
    };
    let target_domains = TargetDomains::try_new(&httpsig_config, "modoh03.typeq.org").await.unwrap();
    let inner = target_domains.inner.read().await;

    assert_eq!(inner.len(), 4);
    assert!(inner
      .iter()
      .any(|v| v.configs_endpoint_uri.host().unwrap() != "modoh01.typeq.org"));
    assert!(inner
      .iter()
      .any(|v| v.configs_endpoint_uri.host().unwrap() != "modoh02.typeq.org"));
    assert!(inner
      .iter()
      .any(|v| v.configs_endpoint_uri.host().unwrap() != "dnsauth.typeq.org"));
    assert!(inner.iter().any(|v| v.configs_endpoint_uri.host().unwrap() != "example.com"));
    assert!(inner
      .iter()
      .all(|v| v.configs_endpoint_uri.host().unwrap() != "modoh03.typeq.org"))
  }
}
