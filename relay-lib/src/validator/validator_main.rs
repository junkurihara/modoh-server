use crate::{
  constants::{EXPECTED_MAX_JWKS_SIZE, JWKS_REFETCH_TIMEOUT_SEC, VALIDATOR_USER_AGENT},
  error::*,
  hyper_client::HttpClient,
};
use async_trait::async_trait;
use auth_validator::{
  reexports::{JWTClaims, NoCustomClaims},
  JwksHttpClient, TokenValidator, ValidationConfig,
};
use http::{header, HeaderValue, Method, Request};
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::{Body, Buf, Bytes};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::connect::{Connect, HttpConnector};
use serde::de::DeserializeOwned;
use std::{sync::Arc, time::Duration};
use url::Url;

#[async_trait]
/// JwksHttpClient trait implementation for HttpClient
impl<C> JwksHttpClient for HttpClient<C, BoxBody<Bytes, hyper::Error>>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  async fn fetch_jwks<R>(&self, url: &Url) -> std::result::Result<R, anyhow::Error>
  where
    R: DeserializeOwned + Send + Sync,
  {
    let mut req = Request::builder()
      .uri(url.as_str())
      .method(Method::GET)
      .body(Empty::<Bytes>::new().map_err(|never| match never {}).boxed())?;
    let user_agent = format!("{}/{}", VALIDATOR_USER_AGENT, env!("CARGO_PKG_VERSION"));
    req
      .headers_mut()
      .insert(header::USER_AGENT, HeaderValue::from_str(&user_agent)?);

    let jwks_res = tokio::time::timeout(Duration::from_secs(JWKS_REFETCH_TIMEOUT_SEC), self.request(req)).await??;
    let body = jwks_res.into_body();

    let max = body.size_hint().upper().unwrap_or(u64::MAX);
    if max > EXPECTED_MAX_JWKS_SIZE {
      bail!("jwks size is too large: {}", max)
    }
    if max == 0 {
      bail!("jwks size is zero")
    }

    // asynchronously aggregate the chunks of the body
    let body = body.collect().await?.aggregate();

    // try to parse as json with serde_json
    let jwks = serde_json::from_reader::<_, R>(body.reader())?;
    Ok(jwks)
  }
}

/// Wrapper of TokenValidator
pub struct Validator<C, B = BoxBody<Bytes, hyper::Error>>
where
  C: Send + Sync + Connect + Clone + 'static,
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
  HttpClient<C, B>: JwksHttpClient,
{
  pub(super) inner: TokenValidator<HttpClient<C, B>>,
}

impl<C, B> Validator<C, B>
where
  C: Send + Sync + Connect + Clone + 'static,
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
  HttpClient<C, B>: JwksHttpClient,
{
  /// Validate an id token. Return Ok(()) if validation is successful with any one of validation keys.
  pub async fn validate_request<T>(&self, req: &Request<T>) -> HttpResult<JWTClaims<NoCustomClaims>> {
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

impl Validator<HttpsConnector<HttpConnector>> {
  /// Create a new validator
  pub async fn try_new(config: &ValidationConfig, runtime_handle: tokio::runtime::Handle) -> Result<Self> {
    let http_client = HttpClient::new(runtime_handle);
    let inner = TokenValidator::try_new(config, Arc::new(http_client)).await?;
    Ok(Self { inner })
  }
}
