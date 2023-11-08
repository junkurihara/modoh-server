use crate::{constants::*, error::*, globals::Globals, log::*};
use hyper::{
  header,
  http::{HeaderMap, HeaderValue, Method},
  Body, Request, Response, StatusCode,
};
use std::{net::SocketAddr, sync::Arc};

/// build http response with status code of 4xx and 5xx
fn http_error(status_code: StatusCode) -> Result<Response<Body>> {
  let response = Response::builder().status(status_code).body(Body::empty()).unwrap();
  Ok(response)
}

/// parse and check content type and accept headers if both or either of them are "application/oblivious-dns-message".
fn check_content_type<T>(req: &Request<T>) -> std::result::Result<(), Response<Body>> {
  // check content type
  if let Some(content_type) = req.headers().get(header::CONTENT_TYPE) {
    let Ok(ct) = content_type.to_str() else {
      return Err(http_error(StatusCode::BAD_REQUEST).unwrap());
    };
    if ct.to_ascii_lowercase() != ODOH_CONTENT_TYPE {
      return Err(http_error(StatusCode::UNSUPPORTED_MEDIA_TYPE).unwrap());
    }
    return Ok(());
  }

  // check accept
  if let Some(accept) = req.headers().get(header::ACCEPT) {
    let Ok(ac) = accept.to_str() else {
      return Err(http_error(StatusCode::BAD_REQUEST).unwrap());
    };
    let mut ac_split = ac.split(',').map(|s| s.trim().to_ascii_lowercase());
    if !ac_split.any(|s| s == ODOH_ACCEPT) {
      return Err(http_error(StatusCode::NOT_ACCEPTABLE).unwrap());
    }
    return Ok(());
  };

  // neither content type nor accept is "application/oblivious-dns-message"
  Err(http_error(StatusCode::UNSUPPORTED_MEDIA_TYPE).unwrap())
}

/// wrapper of reqwest client
pub struct InnerForwarder {
  /// reqwest client
  pub(super) inner: reqwest::Client,
  /// relay host name
  pub(super) relay_host: String,
  /// url path listening for odoh query
  pub(super) relay_path: String,
  /// max number of subsequent nodes
  pub(super) max_subseq_nodes: usize,
}

impl InnerForwarder {
  /// Serve request as relay
  /// 1. check host, method and listening path: as described in [RFC9230](https://www.rfc-editor.org/rfc/rfc9230.html) and Golang implementation [odoh-server-go](https://github.com/cloudflare/odoh-server-go), only post method is allowed.
  /// 2. check content type: only "application/oblivious-dns-message" is allowed.
  /// 3-a. retrieve query and build new target url
  /// 3-b. retrieve query and check if it is a valid odoh query
  pub async fn serve(&self, req: Request<Body>, peer_addr: SocketAddr) -> Result<hyper::Response<Body>> {
    // TODO: source ip authenticate here?
    // check host
    if req.uri().host() != Some(self.relay_host.as_str()) {
      return http_error(StatusCode::MISDIRECTED_REQUEST);
    };
    // check path
    if req.uri().path() != self.relay_path {
      return http_error(StatusCode::NOT_FOUND);
    };
    // check method
    if req.method() != Method::POST {
      return http_error(StatusCode::METHOD_NOT_ALLOWED);
    };
    // check content type
    if let Err(error_res) = check_content_type(&req) {
      return Ok(error_res);
    };
    // build next hop url
    let current_url = &url::Url::parse(&req.uri().to_string()).map_err(RelayError::InvalidUri)?;
    let nexthop_url = self.build_nexthop_url(current_url)?;

    //TODO: TODO: TODO: TODO:
    // check if it is a valid odoh query and serve it!

    // TODO: next hop domain name check here?
    todo!()
  }
  /// Build inner forwarder
  pub fn try_new(globals: &Arc<Globals>) -> Result<Self> {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(ODOH_CONTENT_TYPE));
    headers.insert(header::ACCEPT, HeaderValue::from_static(ODOH_ACCEPT));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(ODOH_CACHE_CONTROL));

    let inner = reqwest::Client::builder()
      .user_agent(FORWARDER_UA)
      .timeout(globals.relay_config.timeout)
      .trust_dns(true)
      .default_headers(headers)
      .build()?;
    let relay_host = globals.relay_config.hostname.clone();
    let relay_path = globals.relay_config.path.clone();
    let max_subseq_nodes = globals.relay_config.max_subseq_nodes;

    Ok(Self {
      inner,
      relay_host,
      relay_path,
      max_subseq_nodes,
    })
  }
}
