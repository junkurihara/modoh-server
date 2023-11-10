use crate::{constants::*, error::*, globals::Globals, log::*};
use futures_util::StreamExt;
use hyper::{
  client::{connect::Connect, HttpConnector},
  header,
  http::{request::Parts, HeaderMap, HeaderValue, Method},
  Body, Client, Request, Response, StatusCode,
};
use hyper_rustls::HttpsConnector;
use std::{net::SocketAddr, sync::Arc};
use url::Url;

/// build http response with status code of 4xx and 5xx
fn http_error(status_code: StatusCode) -> Result<Response<Body>> {
  let response = Response::builder().status(status_code).body(Body::empty()).unwrap();
  Ok(response)
}

/// parse and check content type and accept headers if both or either of them are "application/oblivious-dns-message".
fn check_content_type<T>(req: &Request<T>) -> HttpResult<()> {
  // check content type
  if let Some(content_type) = req.headers().get(header::CONTENT_TYPE) {
    let Ok(ct) = content_type.to_str() else {
      return Err(HttpError::InvalidContentTypeString);
    };
    if ct.to_ascii_lowercase() != ODOH_CONTENT_TYPE {
      return Err(HttpError::NotObliviousDnsMessageContentType);
    }
    return Ok(());
  }

  // check accept
  if let Some(accept) = req.headers().get(header::ACCEPT) {
    let Ok(ac) = accept.to_str() else {
      return Err(HttpError::InvalidAcceptString);
    };
    let mut ac_split = ac.split(',').map(|s| s.trim().to_ascii_lowercase());
    if !ac_split.any(|s| s == ODOH_ACCEPT) {
      return Err(HttpError::NotObliviousDnsMessageAccept);
    }
    return Ok(());
  };

  // neither content type nor accept is "application/oblivious-dns-message"
  Err(HttpError::NoContentTypeAndAccept)
}

/// Read encrypted query from request body
async fn read_body(body: &mut Body) -> HttpResult<Vec<u8>> {
  let mut sum_size = 0;
  let mut query = vec![];
  while let Some(chunk) = body.next().await {
    let chunk = chunk.map_err(|_| HttpError::TooLargeRequestBody)?;
    sum_size += chunk.len();
    if sum_size >= MAX_DNS_QUESTION_LEN {
      return Err(HttpError::TooLargeRequestBody);
    }
    query.extend(chunk);
  }
  Ok(query)
}

/// Get HOST header and/or host name in url line in http request
/// Returns Err if both are specified and inconsistent, or if none of them is specified.
/// Note that port is dropped even if specified.
fn inspect_get_host(req: &Request<Body>) -> HttpResult<String> {
  let drop_port = |v: &str| {
    v.split(':')
      .next()
      .ok_or_else(|| HttpError::InvalidHost)
      .map(|s| s.to_string())
  };

  let host_header = req.headers().get(header::HOST).map(|v| v.to_str().map(drop_port));
  let host_url = req.uri().host().map(drop_port);

  match (host_header, host_url) {
    (Some(Ok(Ok(hh))), Some(Ok(hu))) => {
      if hh != hu {
        return Err(HttpError::InvalidHost);
      }
      Ok(hh)
    }
    (Some(Ok(Ok(hh))), None) => Ok(hh),
    (None, Some(Ok(hu))) => Ok(hu),
    _ => Err(HttpError::InvalidHost),
  }
}

/// wrapper of reqwest client
pub struct InnerForwarder<C, B = Body>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  /// hyper client
  pub(super) inner: Client<C, B>,
  /// request default headers
  pub(super) request_headers: HeaderMap,
  /// relay host name
  pub(super) relay_host: String,
  /// url path listening for odoh query
  pub(super) relay_path: String,
  /// max number of subsequent nodes
  pub(super) max_subseq_nodes: usize,
}

impl<C> InnerForwarder<C>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  /// Serve request as relay
  /// 1. check host, method and listening path: as described in [RFC9230](https://datatracker.ietf.org/doc/rfc9230/) and Golang implementation [odoh-server-go](https://github.com/cloudflare/odoh-server-go), only post method is allowed.
  /// 2. check content type: only "application/oblivious-dns-message" is allowed.
  /// 3-a. retrieve query and build new target url
  /// 3-b. retrieve query and check if it is a valid odoh query
  /// 4. forward request to next hop
  /// 5. return response after appending "Proxy-Status" header with a received-status param as described in [RFC9230, Section 4.3](https://datatracker.ietf.org/doc/rfc9230/).
  /// c.f., "Proxy-Status" [RFC9209](https://datatracker.ietf.org/doc/rfc9209).
  pub async fn serve(&self, req: Request<Body>, peer_addr: SocketAddr) -> Result<hyper::Response<Body>> {
    // TODO: source ip authenticate here?

    // check host
    let host = match inspect_get_host(&req) {
      Ok(host) => host,
      Err(e) => {
        return http_error(StatusCode::from(e));
      }
    };
    if host != self.relay_host {
      return http_error(StatusCode::from(HttpError::InvalidHost));
    }
    // check path
    if req.uri().path() != self.relay_path {
      return http_error(StatusCode::from(HttpError::InvalidPath));
    };
    // check method
    if req.method() != Method::POST {
      return http_error(StatusCode::from(HttpError::InvalidMethod));
    };
    // check content type
    if let Err(error_res) = check_content_type(&req) {
      return http_error(StatusCode::from(error_res));
    };
    // build next hop url
    let Ok(current_url) = &url::Url::parse(&format!(
      "https://{}{}",
      host,
      &req.uri().path_and_query().map(|v| v.as_str()).unwrap_or("")
    )) else {
      return http_error(StatusCode::from(HttpError::InvalidUrl));
    };
    let nexthop_url = match self.build_nexthop_url(current_url) {
      Ok(url) => url,
      Err(e) => {
        error!("(M)ODoH next hop url build error: {}", e);
        return http_error(StatusCode::from(e));
      }
    };
    debug!("(M)ODoH next hop url: {}", nexthop_url.as_str());

    // TODO: next hop domain name check here?

    // split request into parts and body to manipulate them later
    let (mut parts, mut body) = req.into_parts();
    // check if body is a valid odoh query and serve it
    let encrypted_query = match read_body(&mut body).await {
      Ok(query) => query,
      Err(e) => {
        return http_error(StatusCode::from(e));
      }
    };
    if encrypted_query.is_empty() {
      return http_error(StatusCode::from(HttpError::NoBodyInRequest));
    }

    // Forward request to next hop: Only post method is allowed in ODoH
    if let Err(e) = self.update_request_parts(&nexthop_url, &mut parts) {
      return http_error(StatusCode::from(e));
    }
    let updated_request = Request::from_parts(parts, Body::from(encrypted_query.to_owned()));
    let mut response = match self.inner.request(updated_request).await {
      Ok(res) => res,
      Err(e) => {
        warn!("Upstream query error: {}", e);
        return http_error(StatusCode::from(HttpError::SendRequestError(e)));
      }
    };
    // Inspect and update response
    if let Err(e) = self.inspect_update_response(&mut response) {
      return http_error(StatusCode::from(e));
    }

    Ok(response)
  }

  /// Update request headers and clear information as much as possible
  fn update_request_parts(&self, nexthop_url: &Url, parts: &mut Parts) -> HttpResult<()> {
    parts.method = Method::POST;
    parts.uri = hyper::Uri::try_from(nexthop_url.as_str()).map_err(|e| {
      error!("Uri parse error in request update: {e}");
      HttpError::InvalidUrl
    })?;
    parts.headers.clear();
    parts.headers = self.request_headers.clone();
    parts.extensions.clear();
    parts.version = hyper::Version::default();

    Ok(())
  }

  /// inspect and update response
  /// (M)ODoH response MUST NOT be cached as specified in [RFC9230](https://datatracker.ietf.org/doc/rfc9230/),
  /// and hence "no-cache, no-store" is set (overwritten) in cache-control header.
  /// Also "Proxy-Status" header with a received-status param is appended (overwritten) as described in [RFC9230, Section 4.3](https://datatracker.ietf.org/doc/rfc9230/).
  /// c.f., "Proxy-Status" [RFC9209](https://datatracker.ietf.org/doc/rfc9209).
  fn inspect_update_response(&self, response: &mut Response<Body>) -> HttpResult<()> {
    let status = response.status();
    let proxy_status = format!("received-status={}", status);

    // inspect headers (content-type)
    let headers = response.headers();
    let Some(content_type) = headers.get(&header::CONTENT_TYPE) else {
      return Err(HttpError::InvalidResponseContentType);
    };
    let Ok(ct) = content_type.to_str() else {
      return Err(HttpError::InvalidResponseContentType);
    };
    if ct.to_ascii_lowercase() != ODOH_CONTENT_TYPE {
      return Err(HttpError::NotObliviousDnsMessageContentType);
    };

    // update header
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(ODOH_CACHE_CONTROL));
    headers.insert("proxy-status", HeaderValue::from_str(proxy_status.as_str()).unwrap());
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));

    Ok(())
  }
}

impl InnerForwarder<HttpsConnector<HttpConnector>, Body> {
  /// Build inner forwarder
  pub fn try_new(globals: &Arc<Globals>) -> Result<Self> {
    // default headers for request
    let mut request_headers = HeaderMap::new();
    request_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(ODOH_CONTENT_TYPE));
    request_headers.insert(header::ACCEPT, HeaderValue::from_static(ODOH_ACCEPT));
    request_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(ODOH_CACHE_CONTROL));
    request_headers.insert(header::USER_AGENT, HeaderValue::from_static(FORWARDER_UA));

    // build hyper client with rustls and webpki, only https is allowed
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
      .with_webpki_roots()
      .https_only()
      .enable_http1()
      .enable_http2()
      .build();
    let inner = Client::builder().build::<_, Body>(connector);

    let relay_host = globals.relay_config.hostname.clone();
    let relay_path = globals.relay_config.path.clone();
    let max_subseq_nodes = globals.relay_config.max_subseq_nodes;

    Ok(Self {
      inner,
      request_headers,
      relay_host,
      relay_path,
      max_subseq_nodes,
    })
  }
}