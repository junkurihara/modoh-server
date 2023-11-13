mod count;
mod forwarder;
mod forwarder_handle_url;
mod relay_main;
mod socket;

use crate::error::*;
use hyper::{Body, Response, StatusCode};
pub use relay_main::Relay;

/// build http response with status code of 4xx and 5xx
fn http_error(status_code: StatusCode) -> Result<Response<Body>> {
  let response = Response::builder().status(status_code).body(Body::empty()).unwrap();
  Ok(response)
}
