use crate::{auth::TokenAuthenticator, error::*};
use hyper::{header, Body, Request};
use jwt_simple::prelude::{JWTClaims, NoCustomClaims};
use std::sync::Arc;

/// wrapper of TokenAuthenticator
pub struct InnerAuthenticator {
  inner: Arc<TokenAuthenticator>,
}

impl InnerAuthenticator {
  /// Create a new authenticator
  pub fn new(inner: Arc<TokenAuthenticator>) -> Self {
    Self { inner }
  }

  /// Validate an id token. Return Ok(()) if validation is successful with any one of validation keys.
  pub async fn validate(&self, req: &Request<Body>) -> HttpResult<JWTClaims<NoCustomClaims>> {
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
      Err(e) => return Err(e),
    };
    if claims.is_empty() {
      return Err(HttpError::InvalidToken);
    }

    Ok(claims.get(0).unwrap().clone())
  }
}
