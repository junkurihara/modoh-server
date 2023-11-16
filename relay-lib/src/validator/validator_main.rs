use crate::{
  constants::{JWKS_REFETCH_TIMEOUT_SEC, VALIDATOR_USER_AGENT},
  error::*,
  log::*,
};
use async_trait::async_trait;
use auth_validator::{
  reexports::{JWTClaims, NoCustomClaims},
  JwksHttpClient, TokenValidator, ValidationConfig,
};
use hyper::{body::Body, header, Request};
use serde::de::DeserializeOwned;
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use url::Url;

/// Wrapper of reqwest::client::Client
pub(super) struct HttpClient {
  inner: reqwest::Client,
}

#[async_trait]
/// JwksHttpClient trait implementation for HttpClient
impl JwksHttpClient for HttpClient {
  async fn fetch_jwks<R>(&self, url: &Url) -> std::result::Result<R, anyhow::Error>
  where
    R: DeserializeOwned + Send + Sync,
  {
    let jwks_res = self.inner.get(url.clone()).send().await?;
    let jwks = jwks_res.json::<R>().await?;
    Ok(jwks)
  }
}

/// Wrapper of TokenValidator
pub struct Validator {
  pub(super) inner: Arc<TokenValidator<HttpClient>>,
}

impl Validator {
  /// Create a new validator
  pub async fn try_new(config: &ValidationConfig) -> Result<Self> {
    let inner = reqwest::Client::builder()
      .user_agent(format!("{}/{}", VALIDATOR_USER_AGENT, env!("CARGO_PKG_VERSION")))
      .timeout(Duration::from_secs(JWKS_REFETCH_TIMEOUT_SEC))
      .build()
      .map_err(|e| {
        error!("{e}");
        RelayError::BuildValidatorError
      })?;
    let http_client = HttpClient { inner };
    let inner = TokenValidator::try_new(config, Arc::new(RwLock::new(http_client))).await?;
    Ok(Self { inner: Arc::new(inner) })
  }

  /// Validate an id token. Return Ok(()) if validation is successful with any one of validation keys.
  pub async fn validate_request(&self, req: &Request<Body>) -> HttpResult<JWTClaims<NoCustomClaims>> {
    let Some(auth_header) = req.headers().get(header::AUTHORIZATION) else {
      return Err(HttpError::NoAuthorizationHeader);
    };
    let Ok(auth_header) = auth_header.to_str() else {
      return Err(HttpError::InvalidAuthorizationHeader);
    };
    if !auth_header.starts_with("Bearer ") {
      return Err(HttpError::InvalidAuthorizationHeader);
    }

    let token = auth_header.trim_start_matches("Bearer ");
    let claims = match self.inner.validate(token).await {
      Ok(claims) => claims,
      Err(_) => return Err(HttpError::InvalidToken),
    };
    if claims.is_empty() {
      return Err(HttpError::InvalidToken);
    }

    Ok(claims.get(0).unwrap().clone())
  }
}
