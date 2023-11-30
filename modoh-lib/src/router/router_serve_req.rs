use crate::{
  error::*,
  hyper_body::{passthrough_response, synthetic_error_response, synthetic_response, BoxBody, IncomingOr},
  log::*,
  relay::InnerRelay,
  target::InnerTarget,
  validator::Validator,
};
use hyper::{body::Incoming, header, Request, StatusCode};
use hyper_util::client::legacy::connect::Connect;
use std::{net::SocketAddr, sync::Arc};

/// Service wrapper with validation
pub async fn serve_request_with_validation<C>(
  req: Request<Incoming>,
  peer_addr: SocketAddr,
  hostname: String,
  relay: Option<Arc<InnerRelay<C>>>,
  target: Option<Arc<InnerTarget>>,
  validator: Option<Arc<Validator<C>>>,
) -> Result<hyper::Response<IncomingOr<BoxBody>>>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  // validation with header
  if let (Some(validator), true) = (validator, req.headers().contains_key(header::AUTHORIZATION)) {
    debug!("execute token validation");
    let claims = match validator.validate_request(&req).await {
      Ok(claims) => claims,
      Err(e) => {
        warn!("token validation failed: {}", e);
        return synthetic_error_response(StatusCode::from(e));
      }
    };
    debug!(
      "token validation passed: subject {}",
      claims.subject.as_deref().unwrap_or("")
    );
  }
  // check path and route request
  let path = req.uri().path();
  // match odoh config, without checking allowed ip address
  // odoh config should be served without access control
  if target.as_ref().map(|t| t.odoh_configs_path == path).unwrap_or(false) {
    return match target.unwrap().serve_odoh_configs(req).await {
      Ok(res) => synthetic_response(res),
      Err(e) => {
        debug!("ODoH config service failed to serve: {}", e);
        synthetic_error_response(StatusCode::from(e))
      }
    };
  }

  // TODO: source ip access control here
  // for authorized ip addresses, maintain blacklist (error metrics) at each relay for given requests
  // domain check should be done in forwarder.

  // match modoh relay
  if relay.as_ref().map(|r| r.relay_path == path).unwrap_or(false) {
    // serve query as relay
    return match relay.unwrap().serve(req.map(IncomingOr::Left)).await {
      Ok(res) => passthrough_response(res),
      Err(e) => {
        debug!("Relay failed to serve: {}", e);
        synthetic_error_response(StatusCode::from(e))
      }
    };
  }
  // match modoh target
  if target.as_ref().map(|t| t.target_path == path).unwrap_or(false) {
    return match target.unwrap().serve(req).await {
      Ok(res) => synthetic_response(res),
      Err(e) => {
        debug!("Target failed to serve: {}", e);
        synthetic_error_response(StatusCode::from(e))
      }
    };
  }

  synthetic_error_response(StatusCode::NOT_FOUND)
}
