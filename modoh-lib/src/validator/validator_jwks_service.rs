use super::validator_main::Validator;
use crate::{constants::JWKS_REFETCH_DELAY_SEC, error::*, hyper_client::HttpClient, log::*};
use auth_validator::JwksHttpClient;
use futures::{select, FutureExt};
use hyper::body::Body;
use hyper_util::client::legacy::connect::Connect;
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;

impl<C, B> Validator<C, B>
where
  C: Send + Sync + Connect + Clone + 'static,
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
  HttpClient<C, B>: JwksHttpClient,
{
  /// Check token expiration every 60 secs, and refresh if the token is about to expire.
  pub async fn start_service(&self, term_notify: Option<Arc<tokio::sync::Notify>>) -> Result<()> {
    info!("Start periodic jwks retrieval service");

    match term_notify {
      Some(term) => {
        select! {
          _ = self.jwks_retrieval_service().fuse() => {
            warn!("Jwks service got down. Possibly failed to refresh or login.");
          }
          _ = term.notified().fuse() => {
            info!("Jwks service receives term signal");
          }
        }
      }
      None => {
        self.jwks_retrieval_service().await?;
        warn!("Jwks service got down. Possibly failed to refresh or login.");
      }
    }
    Ok(())
  }

  /// periodic refresh checker
  async fn jwks_retrieval_service(&self) -> Result<()> {
    loop {
      sleep(Duration::from_secs(JWKS_REFETCH_DELAY_SEC)).await;

      if let Err(e) = self.inner.refetch_all_jwks().await {
        error!("Failed to retrieve jwks, Keep validation key unchanged: {}", e);
      } else {
        info!("Successfully retrieved jwks");
      };
    }
  }
}
