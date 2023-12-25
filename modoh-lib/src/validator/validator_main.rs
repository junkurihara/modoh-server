use crate::{
  constants::{EXPECTED_MAX_JWKS_SIZE, JWKS_REFETCH_TIMEOUT_SEC, VALIDATOR_USER_AGENT},
  error::*,
  globals::Globals,
  hyper_body::{BoxBody, IncomingOr},
  hyper_client::HttpClient,
};
use async_trait::async_trait;
use auth_validator::{reexports::Claims, JwksHttpClient, TokenValidator};
use http::{header, HeaderValue, Method, Request};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Buf, Bytes};
use hyper_util::client::legacy::connect::Connect;
use serde::de::DeserializeOwned;
use std::{sync::Arc, time::Duration};
use tracing::instrument;
use url::Url;

#[async_trait]
/// JwksHttpClient trait implementation for HttpClient
impl<C> JwksHttpClient for HttpClient<C, IncomingOr<BoxBody>>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  #[instrument(name = "fetch_jwks", skip(self))]
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

    let jwks_res = tokio::time::timeout(
      Duration::from_secs(JWKS_REFETCH_TIMEOUT_SEC),
      self.request(req.map(IncomingOr::Right)),
    )
    .await??;
    if !jwks_res.status().is_success() {
      bail!("jwks request failed: {url} {}", jwks_res.status())
    }
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
pub struct Validator<C, B = IncomingOr<BoxBody>>
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
  #[instrument(name = "validate_request", skip_all)]
  /// Validate an id token. Return Ok(()) if validation is successful with any one of validation keys.
  pub async fn validate_request<T>(&self, req: &Request<T>) -> HttpResult<Claims> {
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

  /// Create a new validator
  pub async fn try_new(globals: &Arc<Globals>, http_client: &Arc<HttpClient<C, B>>) -> Result<Arc<Self>> {
    // let http_client = HttpClient::try_new(globals.runtime_handle.clone())?;
    let config = globals
      .service_config
      .validation
      .as_ref()
      .ok_or(MODoHError::BuildValidatorError)?;
    let inner = TokenValidator::try_new(config, http_client.clone()).await?;
    let validator = Arc::new(Self { inner });

    let validator_clone = validator.clone();
    let term_notify = globals.term_notify.clone();

    globals
      .runtime_handle
      .spawn(async move { validator_clone.start_service(term_notify).await.ok() });

    Ok(validator)
  }
}
