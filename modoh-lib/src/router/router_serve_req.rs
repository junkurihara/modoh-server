use crate::{
  error::*,
  hyper_body::{passthrough_response, synthetic_error_response, synthetic_response, BoxBody, IncomingOr},
  relay::InnerRelay,
  request_filter::RequestFilter,
  target::InnerTarget,
  trace::*,
  validator::Validator,
};
use hyper::{body::Incoming, header, Request, StatusCode};
use hyper_util::client::legacy::connect::Connect;
use std::{net::SocketAddr, sync::Arc};
use tracing::Instrument as _;

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
    let token_validation_span = tracing::info_span!("token_validation");
    let _enter = token_validation_span.enter();
    debug!(monotonic_counter.token_validation = 1_u64, "execute token validation");
    let claims = match validator.validate_request(&req).in_current_span().await {
      Ok(claims) => claims,
      Err(e) => {
        warn!(
          monotonic_counter.token_validation_error = 1_u64,
          "token validation failed: {}", e
        );
        return synthetic_error_response(StatusCode::from(e));
      }
    };
    debug!(
      sub = claims.custom.get("sub").and_then(|v| v.as_str()).unwrap_or(""),
      "passed token validation",
    );
    token_validated = true;
  }

  // check path and route request
  let path = req.uri().path();
  // match odoh config, without checking allowed ip address
  // odoh config should be served without access control
  if target.as_ref().map(|t| t.odoh_configs_path == path).unwrap_or(false) {
    let odoh_config_span = tracing::info_span!("odoh_config");
    let _enter = odoh_config_span.enter();
    debug!(monotonic_counter.odoh_configs = 1_u64, "odoh_configs request");
    return match target.unwrap().serve_odoh_configs(req).in_current_span().await {
      Ok(res) => synthetic_response(res),
      Err(e) => {
        warn!(
          monotonic_counter.odoh_configs_error = 1_u64,
          "ODoH config service failed to serve: {}", e
        );
        synthetic_error_response(StatusCode::from(e))
      }
    };
  }

  // Source ip access control here when we didn't have a chance to validate token.
  // For authorized ip addresses, maintain blacklist (error metrics) at each relay for given requests.
  // Domain check should be done in forwarder.
  if !token_validated {
    let src_ip_ac_span = tracing::info_span!("src_ip_access_control");
    let _enter = src_ip_ac_span.enter();
    debug!(
      monotonic_counter.src_ip_access_control = 1_u64,
      "execute source ip access control"
    );
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
        debug!(
          monotonic_counter.src_ip_access_control_rejected = 1_u64,
          "rejected source ip address: {}", e
        );
        return synthetic_error_response(StatusCode::from(e));
      }
      debug!("passed source ip address access control");
    }
  } else {
    debug!("skip source ip access control since token was validated.");
  }

  // match modoh relay
  if relay.as_ref().map(|r| r.relay_path == path).unwrap_or(false) {
    // serve query as relay
    let relay_span = tracing::info_span!("relay");
    return match relay
      .unwrap()
      .serve(req.map(IncomingOr::Left))
      .instrument(relay_span)
      .await
    {
      Ok(res) => passthrough_response(res),
      Err(e) => {
        debug!("Relay failed to serve: {}", e);
        synthetic_error_response(StatusCode::from(e))
      }
    };
  }
  // match modoh target
  if target.as_ref().map(|t| t.target_path == path).unwrap_or(false) {
    let target_span = tracing::info_span!("target");
    return match target.unwrap().serve(req).instrument(target_span).await {
      Ok(res) => synthetic_response(res),
      Err(e) => {
        debug!("Target failed to serve: {}", e);
        synthetic_error_response(StatusCode::from(e))
      }
    };
  }

  synthetic_error_response(StatusCode::NOT_FOUND)
}
