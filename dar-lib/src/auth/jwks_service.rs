use super::{
  auth_main::{TokenAuthenticator, TokenAuthenticatorInner},
  validation_key::ValidationKey,
};
use crate::{
  constants::{JWKS_ENDPOINT_PATH, JWKS_REFETCH_DELAY_SEC},
  error::*,
  log::*,
};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;

#[derive(Deserialize, Debug)]
/// Jwks response
pub(super) struct JwksResponse {
  pub keys: Vec<serde_json::Value>,
}

impl TokenAuthenticator {
  /// Check token expiration every 60 secs, and refresh if the token is about to expire.
  pub async fn start_service(&self, term_notify: Option<Arc<tokio::sync::Notify>>) -> Result<()> {
    info!("Start periodic jwks retrieval service");

    match term_notify {
      Some(term) => {
        tokio::select! {
          _ = self.jwks_retrieval_service() => {
            warn!("Auth service got down. Possibly failed to refresh or login.");
          }
          _ = term.notified() => {
            info!("Auth service receives term signal");
          }
        }
      }
      None => {
        self.jwks_retrieval_service().await?;
        warn!("Auth service got down. Possibly failed to refresh or login.");
      }
    }
    Ok(())
  }

  /// periodic refresh checker
  async fn jwks_retrieval_service(&self) -> Result<()> {
    loop {
      let futs = self.inner.iter().map(|each_endpoint| async {
        if let Err(e) = each_endpoint.refetch_jwks().await {
          error!("Failed to retrieve jwks: {}", e);
        };
      });
      futures::future::join_all(futs).await;

      sleep(Duration::from_secs(JWKS_REFETCH_DELAY_SEC)).await;
    }
  }
}

impl TokenAuthenticatorInner {
  /// refetch jwks from the server
  async fn refetch_jwks(&self) -> Result<()> {
    let mut jwks_endpoint = self.token_api.clone();
    jwks_endpoint
      .path_segments_mut()
      .map_err(|_| RelayError::JwksUrlError)?
      .push(JWKS_ENDPOINT_PATH);

    let client = reqwest::Client::new();
    let jwks_res = client
      .get(jwks_endpoint)
      .send()
      .await
      .map_err(|e| {
        error!("Failed to retrieve jwks: {}", e);
        RelayError::JwksRetrievalError
      })?
      .json::<JwksResponse>()
      .await
      .map_err(|e| {
        error!("Failed to parse jwks: {}", e);
        RelayError::JwksRetrievalError
      })?;

    if jwks_res.keys.is_empty() {
      return Err(RelayError::JwksRetrievalError);
    }

    let vks = jwks_res
      .keys
      .iter()
      .map(ValidationKey::from_jwk)
      .collect::<Result<Vec<_>>>()?;

    let mut validation_key_lock = self.validation_keys.write().await;
    validation_key_lock.replace(vks);
    drop(validation_key_lock);

    info!(
      "validation key updated from jwks endpoint: {}/{}",
      self.token_api.as_str(),
      JWKS_ENDPOINT_PATH
    );

    Ok(())
  }
}
