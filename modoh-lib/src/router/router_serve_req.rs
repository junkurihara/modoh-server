use super::Router;
use crate::{
  error::*,
  hyper_body::{passthrough_response, synthetic_error_response, synthetic_response, BoxBody, IncomingOr},
  trace::*,
};
use hyper::{body::Incoming, header, Request, StatusCode};
use hyper_util::client::legacy::connect::Connect;
use std::net::SocketAddr;

/// Service wrapper with validation
pub async fn serve_request_with_validation<C>(
  req: Request<Incoming>,
  peer_addr: SocketAddr,
  router: Router<C>,
) -> Result<hyper::Response<IncomingOr<BoxBody>>>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  let relay = router.inner_relay.clone();
  let target = router.inner_target.clone();
  let validator = router.inner_validator.clone();
  let request_filter = router.request_filter.clone();

  #[cfg(feature = "metrics")]
  let meters = router.globals.meters.clone();

  //TODO: timeout for each services, which should be shorter than TIMEOUT_SEC in router_main.rs

  // validation with header
  let mut token_validated = false;
  if let (Some(validator), true) = (validator, req.headers().contains_key(header::AUTHORIZATION)) {
    debug!("execute token validation");

    #[cfg(feature = "metrics")]
    meters.token_validation.add(1_u64, &[]);

    let claims = match validator.validate_request(&req).await {
      Ok(claims) => claims,
      Err(e) => {
        warn!("token validation failed: {e}");
        let status_code = StatusCode::from(e);

        #[cfg(feature = "metrics")]
        count_with_http_status_code(&meters.token_validation_result_error, &status_code);

        return synthetic_error_response(status_code);
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
    #[cfg(feature = "metrics")]
    meters.query_odoh_configs.add(1_u64, &[]);

    return match target.unwrap().serve_odoh_configs(req).await {
      Ok(res) => synthetic_response(res),
      Err(e) => {
        warn!("ODoH config service failed to serve: {}", e);
        let status_code = StatusCode::from(e);

        #[cfg(feature = "metrics")]
        count_with_http_status_code(&meters.query_odoh_configs_result_error, &status_code);

        synthetic_error_response(status_code)
      }
    };
  }

  // Source ip access control here when we didn't have a chance to validate token.
  // For authorized ip addresses, maintain blacklist (error metrics) at each relay for given requests.
  // Domain check should be done in forwarder.
  if !token_validated {
    #[cfg(feature = "metrics")]
    meters.src_ip_access_control.add(1_u64, &[]);

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
        debug!("rejected source ip address {}: {}", peer_ip_adder, e);
        let status_code = StatusCode::from(e);

        #[cfg(feature = "metrics")]
        count_with_http_status_code(&meters.src_ip_access_control_result_rejected, &status_code);

        return synthetic_error_response(status_code);
      }
      debug!("passed source ip address access control");
    }
  } else {
    debug!("skip source ip access control since token was validated.");
  }

  // match modoh relay
  if relay.as_ref().map(|r| r.relay_path == path).unwrap_or(false) {
    // serve query as relay
    #[cfg(feature = "metrics")]
    {
      meters.query_relaying.add(1_u64, &[]);
      if token_validated {
        meters.query_token_validated_relaying.add(1_u64, &[]);
      }
    }

    return match relay.unwrap().serve(req.map(IncomingOr::Left)).await {
      Ok(res) => {
        #[cfg(feature = "metrics")]
        count_with_http_status_code(&meters.query_relaying_result_responded, &res.status());

        passthrough_response(res)
      }
      Err(e) => {
        debug!("Relay failed to serve: {}", e);
        let status_code = StatusCode::from(e);

        #[cfg(feature = "metrics")]
        count_with_http_status_code(&meters.query_relaying_result_error, &status_code);

        synthetic_error_response(status_code)
      }
    };
  }
  // match modoh target
  if target.as_ref().map(|t| t.target_path == path).unwrap_or(false) {
    #[cfg(feature = "metrics")]
    {
      meters.query_target.add(1_u64, &[]);
      if token_validated {
        meters.query_token_validated_target.add(1_u64, &[]);
      }
    }

    return match target.unwrap().serve(req).await {
      Ok(res) => {
        #[cfg(feature = "metrics")]
        count_with_http_status_code(&meters.query_target_result_responded, &res.status());

        synthetic_response(res)
      }
      Err(e) => {
        debug!("Target failed to serve: {}", e);
        let status_code = StatusCode::from(e);

        #[cfg(feature = "metrics")]
        count_with_http_status_code(&meters.query_target_result_error, &status_code);

        synthetic_error_response(status_code)
      }
    };
  }

  synthetic_error_response(StatusCode::NOT_FOUND)
}

/// Counter with status code
#[cfg(feature = "metrics")]
fn count_with_http_status_code(counter: &opentelemetry::metrics::Counter<u64>, status_code: &StatusCode) {
  let status_code = status_code.as_u16().to_string();
  counter.add(1_u64, &[opentelemetry::KeyValue::new("status_code", status_code)]);
}
