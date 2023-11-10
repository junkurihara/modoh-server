use super::validation_key::ValidationKey;
use crate::{error::RelayError, globals::AuthConfig};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Authenticator for ID token
pub struct TokenAuthenticator {
  /// Keys for each token API
  pub(crate) inner: Arc<Vec<TokenAuthenticatorInner>>,
}

/// Inner state of the authenticator
pub struct TokenAuthenticatorInner {
  /// Token API endpoint
  pub(crate) token_api: url::Url,
  /// Validation key retrieved from the server
  pub(crate) validation_keys: Arc<RwLock<Option<Vec<ValidationKey>>>>,
}

impl TryFrom<&AuthConfig> for TokenAuthenticator {
  type Error = RelayError;

  fn try_from(auth_config: &AuthConfig) -> Result<Self, Self::Error> {
    let inner = auth_config
      .inner
      .iter()
      .map(|each| {
        let token_api = each.token_issuer_url.clone();
        let validation_keys = Arc::new(RwLock::new(None));
        TokenAuthenticatorInner {
          token_api,
          validation_keys,
        }
      })
      .collect::<Vec<_>>();

    Ok(Self { inner: Arc::new(inner) })
  }
}
