use crate::error::*;
use http::{Response, StatusCode};
use http_body_util::{combinators, BodyExt, Either, Empty};
use hyper::body::{Bytes, Incoming};

/// Type for synthetic boxed body
pub(crate) type BoxBody = combinators::BoxBody<Bytes, hyper::Error>;
/// Type for either passthrough body or synthetic body
pub(crate) type EitherBody = Either<Incoming, BoxBody>;

/// helper function to build http response with passthrough body
pub(crate) fn passthrough_response(response: Response<Incoming>) -> Result<Response<EitherBody>> {
  Ok(response.map(EitherBody::Left))
}

/// build http response with status code of 4xx and 5xx
pub(crate) fn synthetic_error_response(status_code: StatusCode) -> Result<Response<EitherBody>> {
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
