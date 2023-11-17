mod count;
mod forwarder;
mod forwarder_handle_url;
mod relay_main;
mod socket;

use crate::error::*;
use http::{Response, StatusCode};
use http_body_util::{combinators, BodyExt, Either, Empty};
use hyper::body::{Bytes, Incoming};
use tokio::runtime::Handle;

pub use relay_main::Relay;

#[derive(Clone)]
/// Executor for hyper
struct LocalExecutor {
  runtime_handle: Handle,
}

impl LocalExecutor {
  fn new(runtime_handle: Handle) -> Self {
    LocalExecutor { runtime_handle }
  }
}

impl<F> hyper::rt::Executor<F> for LocalExecutor
where
  F: std::future::Future + Send + 'static,
  F::Output: Send,
{
  fn execute(&self, fut: F) {
    self.runtime_handle.spawn(fut);
  }
}

/// Type for synthetic body of http error response
type BoxBody = combinators::BoxBody<Bytes, hyper::Error>;
/// Type for either passthrough body or synthetic body
type EitherBody = Either<Incoming, BoxBody>;

/// helper function to build http response with passthrough body
fn passthrough_response(response: Response<Incoming>) -> Result<Response<EitherBody>> {
  Ok(response.map(EitherBody::Left))
}

/// build http response with status code of 4xx and 5xx
fn synthetic_error_response(status_code: StatusCode) -> Result<Response<EitherBody>> {
  let res = Response::builder()
    .status(status_code)
    .body(EitherBody::Right(BoxBody::new(empty())))
    .unwrap();
  Ok(res)
}

/// helper function to build a empty body
fn empty() -> BoxBody {
  Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}
