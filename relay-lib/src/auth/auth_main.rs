use super::validation_key::ValidationKey;
use crate::{error::*, globals::AuthConfig, log::*};
use futures::future::join_all;
use jwt_simple::prelude::{JWTClaims, NoCustomClaims, VerificationOptions};
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
  /// Validation options
  pub(crate) validation_options: VerificationOptions,
}

impl TryFrom<&AuthConfig> for TokenAuthenticator {
  type Error = RelayError;

  fn try_from(auth_config: &AuthConfig) -> std::result::Result<Self, Self::Error> {
    let inner = auth_config
      .inner
      .iter()
      .map(|each| {
        let token_api = each.token_issuer_url.clone();

        let validation_keys = Arc::new(RwLock::new(None));

        let mut iss = std::collections::HashSet::new();
        iss.insert(each.token_issuer_url.as_str().to_string());
        let mut aud = std::collections::HashSet::new();
        aud.extend(each.client_ids.iter().map(|s| s.to_string()));
        let validation_options = VerificationOptions {
          allowed_issuers: Some(iss),
          allowed_audiences: Some(aud),
          ..Default::default()
        };

        TokenAuthenticatorInner {
          token_api,
          validation_keys,
          validation_options,
        }
      })
      .collect::<Vec<_>>();

    Ok(Self { inner: Arc::new(inner) })
  }
}

impl TokenAuthenticator {
  /// Validate an id token. Return Ok(()) if validation is successful with any one of validation keys.
  pub async fn validate(&self, id_token: &str) -> Result<Vec<JWTClaims<NoCustomClaims>>> {
    let futures = self.inner.iter().map(|each| async move {
      let validation_keys = each.validation_keys.read().await;
      if let Some(validation_keys) = validation_keys.as_ref() {
        let res = validation_keys
          .iter()
          .map(|vk| vk.verify(id_token, Some(&each.validation_options)))
          .filter_map(|res| {
            if res.as_ref().is_err() {
              debug!("Failed to validate id token: {}", res.as_ref().err().unwrap());
            }
            res.ok()
          })
          .collect::<Vec<_>>();
        return Ok(res);
      }
      Err(RelayError::ValidationFailed)
    });

    let results = join_all(futures)
      .await
      .into_iter()
      .filter_map(|res| res.ok())
      .flatten()
      .collect::<Vec<_>>();

    if results.is_empty() {
      debug!("Empty validation results");
      return Err(RelayError::ValidationFailed);
    }
    Ok(results)
  }
}
