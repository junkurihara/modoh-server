use crate::{
  error::*,
  hyper_body::{passthrough_response, synthetic_error_response, synthetic_response, BoxBody, IncomingOr},
  log::*,
  relay::InnerRelay,
  request_filter::RequestFilter,
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
  _hostname: String,
  relay: Option<Arc<InnerRelay<C>>>,
  target: Option<Arc<InnerTarget>>,
  validator: Option<Arc<Validator<C>>>,
  request_filter: Option<Arc<RequestFilter>>,
) -> Result<hyper::Response<IncomingOr<BoxBody>>>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  //TODO: timeout for each services, which should be shorter than TIMEOUT_SEC in router_main.rs

  // validation with header
  let mut token_validated = false;
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
      claims.custom.get("sub").and_then(|v| v.as_str()).unwrap_or("")
    );
    token_validated = true;
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

  // Source ip access control here when we didn't have a chance to validate token.
  // For authorized ip addresses, maintain blacklist (error metrics) at each relay for given requests.
  // Domain check should be done in forwarder.
  if !token_validated {
    debug!("execute source ip access control");
    let peer_ip_adder = peer_addr.ip();
    let req_header = req.headers();
    let filter_result = request_filter.as_ref().and_then(|filter| {
      filter
        .inbound_filter
        .as_ref()
        .map(|inbound| inbound.is_allowed_request(&peer_ip_adder, req_header))
    });
    if let Some(res) = filter_result {
      if let Err(e) = res {
        debug!("Source ip address is filtered: {}", e);
        return synthetic_error_response(StatusCode::from(e));
      }
      debug!("Passed source ip address access control");
    }
  } else {
    debug!("skip source ip access control since token was validated.");
  }

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
