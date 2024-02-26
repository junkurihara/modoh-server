use crate::{error::*, ServiceConfig};
use httpsig_proto::{HttpSigKeyTypes, HttpSigPublicKeys};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

/// Http message signature service state
pub(crate) struct HttpsigServiceState {
  /// key types
  pub(crate) key_types: Vec<HttpSigKeyTypes>,
  /// httpsig configs including key pairs and serialized public keys
  pub(crate) configs: RwLock<HttpSigPublicKeys>,
  /// rotation period
  pub(crate) rotation_period: Duration,
  // /// TODO: periodically refetched configurations from other servers
  // pub(crate) external_configs: RwLock<HashMap<DomainName, HttpSigConfigs>>,
  // /// TODO: periodically refetched configurations from other servers
  // pub(crate) refetch_period: Duration,
  // TODO: refetch service
  // TODO: key id maps
}

impl HttpsigServiceState {
  /// Create a new HttpsigServiceState
  pub fn try_new(service_config: &ServiceConfig) -> Result<Arc<HttpsigServiceState>> {
    let httpsig_key_types = service_config
      .access
      .clone()
      .map(|v| v.httpsig.map(|t| t.key_types).unwrap_or_default())
      .unwrap_or_default();
    let httpsig_configs = HttpSigPublicKeys::new(&httpsig_key_types).map_err(MODoHError::HttpSigConfigError)?;
    let httpsig_configs = RwLock::new(httpsig_configs);
    let rotation_period = service_config
      .access
      .clone()
      .map(|v| v.httpsig.map(|t| t.key_rotation_period).unwrap_or_default())
      .unwrap_or_default();
    Ok(Arc::new(HttpsigServiceState {
      key_types: httpsig_key_types,
      configs: httpsig_configs,
      rotation_period,
    }))
  }
}
