mod handler;

pub(crate) use handler::HttpSigKeysHandler;

use crate::{error::*, ServiceConfig};
use httpsig_proto::{HttpSigKeyTypes, HttpSigPublicKeys};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

/// Http message signature key rotation service state
pub(crate) struct HttpSigKeyRotationState {
  /// key types
  pub(crate) key_types: Vec<HttpSigKeyTypes>,
  /// httpsig configs including key pairs and serialized public keys
  pub(crate) configs: RwLock<HttpSigPublicKeys>,
  /// rotation period
  pub(crate) rotation_period: Duration,
}

impl HttpSigKeyRotationState {
  /// Create a new state
  pub fn try_new(service_config: &ServiceConfig) -> Result<Option<Arc<HttpSigKeyRotationState>>> {
    let httpsig_key_types = service_config
      .access
      .clone()
      .map(|v| v.httpsig.map(|t| t.key_types).unwrap_or_default())
      .unwrap_or_default();
    if httpsig_key_types.is_empty() {
      return Ok(None);
    }

    let httpsig_configs = HttpSigPublicKeys::new(&httpsig_key_types).map_err(MODoHError::HttpSigConfigError)?;
    let httpsig_configs = RwLock::new(httpsig_configs);
    let rotation_period = service_config
      .access
      .clone()
      .map(|v| v.httpsig.map(|t| t.key_rotation_period).unwrap_or_default())
      .unwrap_or_default();
    Ok(Some(Arc::new(HttpSigKeyRotationState {
      key_types: httpsig_key_types,
      configs: httpsig_configs,
      rotation_period,
    })))
  }
}

/// Http message signature key management state
/// TODO: consider the data structure updated by fetcher and used by router, target, relay
pub(crate) struct HttpSigKeyManagementState {
  // /// TODO: periodically refetched configurations from other servers
  // pub(crate) external_configs: RwLock<HashMap<DomainName, HttpSigConfigs>>,
  // /// TODO: periodically refetched configurations from other servers
  // pub(crate) refetch_period: Duration,
  // TODO: refetch service
  // TODO: key id maps
}
