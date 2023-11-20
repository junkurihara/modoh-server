use super::InnerTarget;
use crate::{
  constants::{DNS_QUERY_PARAM, MAX_DNS_QUESTION_LEN},
  error::*,
  hyper_body::BoxBody,
  message_util::{check_content_type, inspect_host, read_request_body, RequestType},
};
use base64::{engine::general_purpose, Engine as _};
use http::{Method, Request, Response};
use hyper::body::Body;

impl InnerTarget {
  /// Serve request as a DoH or (M)ODoH target
  /// 1. check host, method and listening path: as described in [RFC9230](https://datatracker.ietf.org/doc/rfc9230/) and Golang implementation [odoh-server-go](https://github.com/cloudflare/odoh-server-go), only post method is allowed for ODoH. But Get method must be implemented for standard DoH.
  /// 2. check content type: "application/oblivious-dns-message" for MODoH and "application/dns-message" for DoH are allowed.
  /// 3-a. retrieve query and build new target url
  /// 3-b. retrieve query and check if it is a valid doh/odoh query
  /// 4. forward request to upstream resolver and receive a response.
  /// 5. build response and return it to client
  pub async fn serve<B>(&self, req: Request<B>) -> HttpResult<Response<BoxBody>>
  where
    B: Body + Unpin,
  {
    // check host
    inspect_host(&req, &self.target_host)?;
    // check path
    if req.uri().path() != self.target_path {
      return Err(HttpError::InvalidPath);
    };
    // check method
    match *req.method() {
      Method::POST => {
        // check request type
        match check_content_type(&req)? {
          RequestType::DoH => {
            let query = read_request_body(&mut req.into_body()).await?;
            println!("{:?}", query);
            todo!()
          }
          RequestType::ODoH => {
            todo!()
          }
        };
      }
      Method::GET => {
        // check request type, only doh is allowed
        match check_content_type(&req)? {
          RequestType::DoH => {
            let query = query_from_query_string(req)?;
          }
          _ => {
            return Err(HttpError::InvalidMethod);
          }
        };
      }
      _ => return Err(HttpError::InvalidMethod),
    };

    todo!()
  }
}

/// Build DNS query binary from query string in DoH case
fn query_from_query_string<B>(req: Request<B>) -> HttpResult<Vec<u8>> {
  let http_query = req.uri().query().unwrap_or("");
  let question_str = http_query
    .split('&')
    .filter(|v| v.split('=').next() == Some(DNS_QUERY_PARAM))
    .map(|v| v.split('=').nth(1))
    .next()
    .and_then(|v| v)
    .ok_or_else(|| HttpError::InvalidQuery)?;

  if question_str.len() > MAX_DNS_QUESTION_LEN * 4 / 3 {
    return Err(HttpError::InvalidQuery);
  }

  let query = general_purpose::URL_SAFE_NO_PAD
    .decode(question_str)
    .map_err(|_| HttpError::InvalidQuery)?;
  Ok(query)
}
