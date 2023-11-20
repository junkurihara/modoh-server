use crate::{constants::*, error::*, globals::Globals, hyper_client::HttpClient, log::*};
use http::{
  header::{self, HeaderMap, HeaderValue},
  request::Parts,
  Method, Request, Response,
};
use hyper::body::{Body, Incoming};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::connect::{Connect, HttpConnector};
use std::{net::SocketAddr, sync::Arc};
use url::Url;

/// parse and check content type and accept headers if both or either of them are "application/oblivious-dns-message".
fn check_content_type<B>(req: &Request<B>) -> HttpResult<()> {
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
async fn inspect_request_body<B: Body>(body: &B) -> HttpResult<()> {
  let max = body.size_hint().upper().unwrap_or(u64::MAX);
  if max > MAX_DNS_QUESTION_LEN as u64 {
    return Err(HttpError::TooLargeRequestBody);
  }
  if max == 0 {
    return Err(HttpError::NoBodyInRequest);
  }
  // Ok(EitherBody::Left(body))
  Ok(())

  // let mut sum_size = 0;
  // let mut query = vec![];
  // while let Some(chunk) = body.next().await {
  //   let chunk = chunk.map_err(|_| HttpError::TooLargeRequestBody)?;
  //   sum_size += chunk.len();
  //   if sum_size >= MAX_DNS_QUESTION_LEN {
  //     return Err(HttpError::TooLargeRequestBody);
  //   }
  //   query.extend(chunk);
  // }
  // Ok(query)
}

/// Get HOST header and/or host name in url line in http request
/// Returns Err if both are specified and inconsistent, or if none of them is specified.
/// Note that port is dropped even if specified.
fn inspect_get_host<B>(req: &Request<B>) -> HttpResult<String> {
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

/// wrapper of http client
pub struct InnerForwarder<C, B = Incoming>
where
  C: Send + Sync + Connect + Clone + 'static,
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
  /// hyper client
  pub(super) inner: HttpClient<C, B>,
  /// request default headers
  pub(super) request_headers: HeaderMap,
  /// relay host name
  pub(super) relay_host: String,
  /// url path listening for odoh query
  pub(super) relay_path: String,
  /// max number of subsequent nodes
  pub(super) max_subseq_nodes: usize,
}

impl<C, B> InnerForwarder<C, B>
where
  C: Send + Sync + Connect + Clone + 'static,
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
  /// Serve request as relay
  /// 1. check host, method and listening path: as described in [RFC9230](https://datatracker.ietf.org/doc/rfc9230/) and Golang implementation [odoh-server-go](https://github.com/cloudflare/odoh-server-go), only post method is allowed.
  /// 2. check content type: only "application/oblivious-dns-message" is allowed.
  /// 3-a. retrieve query and build new target url
  /// 3-b. retrieve query and check if it is a valid odoh query
  /// 4. forward request to next hop
  /// 5. return response after appending "Proxy-Status" header with a received-status param as described in [RFC9230, Section 4.3](https://datatracker.ietf.org/doc/rfc9230/).
  /// c.f., "Proxy-Status" [RFC9209](https://datatracker.ietf.org/doc/rfc9209).
  pub async fn serve(
    &self,
    req: Request<B>,
    peer_addr: SocketAddr,
    validation_passed: bool,
  ) -> HttpResult<Response<Incoming>> {
    // TODO: source ip access control here?
    // for authorized ip addresses, maintain blacklist (error metrics) at each relay for given requests

    // check host
    let host = inspect_get_host(&req)?;
    if host != self.relay_host {
      return Err(HttpError::InvalidHost);
    }
    // check path
    if req.uri().path() != self.relay_path {
      return Err(HttpError::InvalidPath);
    };
    // check method
    if req.method() != Method::POST {
      return Err(HttpError::InvalidMethod);
    };
    // check content type
    check_content_type(&req)?;

    // build next hop url
    let Ok(current_url) = &url::Url::parse(&format!(
      "https://{}{}",
      host,
      &req.uri().path_and_query().map(|v| v.as_str()).unwrap_or("")
    )) else {
      return Err(HttpError::InvalidUrl);
    };
    let nexthop_url = match self.build_nexthop_url(current_url) {
      Ok(url) => url,
      Err(e) => {
        error!("(M)ODoH next hop url build error: {}", e);
        return Err(e);
      }
    };
    debug!("(M)ODoH next hop url: {}", nexthop_url.as_str());

    // TODO: next hop domain name check here?
    // for authorized domains, maintain blacklist (error metrics) at each relay for given responses

    // split request into parts and body to manipulate them later
    let (mut parts, body) = req.into_parts();
    // check if body does not exceed max size as a DNS query
    inspect_request_body(&body).await?;

    // Forward request to next hop: Only post method is allowed in ODoH
    self.update_request_parts(&nexthop_url, &mut parts)?;
    let updated_request = Request::from_parts(parts, body);

    // let updated_request = Request::from_parts(parts, Body::from(encrypted_query.to_owned()));
    let mut response = match self.inner.request(updated_request).await {
      Ok(res) => res,
      Err(e) => {
        warn!("Upstream query error: {}", e);
        return Err(HttpError::SendRequestError(e));
      }
    };
    // Inspect and update response
    self.inspect_and_update_response_header(&mut response)?;

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

  /// inspect and update response header
  /// (M)ODoH response MUST NOT be cached as specified in [RFC9230](https://datatracker.ietf.org/doc/rfc9230/),
  /// and hence "no-cache, no-store" is set (overwritten) in cache-control header.
  /// Also "Proxy-Status" header with a received-status param is appended (overwritten) as described in [RFC9230, Section 4.3](https://datatracker.ietf.org/doc/rfc9230/).
  /// c.f., "Proxy-Status" [RFC9209](https://datatracker.ietf.org/doc/rfc9209).
  fn inspect_and_update_response_header<T>(&self, response: &mut Response<T>) -> HttpResult<()> {
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

impl InnerForwarder<HttpsConnector<HttpConnector>> {
  /// Build inner forwarder
  pub fn try_new(globals: &Arc<Globals>) -> Result<Self> {
    // default headers for request
    let mut request_headers = HeaderMap::new();
    let user_agent = HeaderValue::from_str(globals.relay_config.http_user_agent.as_str()).map_err(|e| {
      error!("{e}");
      RelayError::BuildForwarderError
    })?;
    request_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(ODOH_CONTENT_TYPE));
    request_headers.insert(header::ACCEPT, HeaderValue::from_static(ODOH_ACCEPT));
    request_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(ODOH_CACHE_CONTROL));
    request_headers.insert(header::USER_AGENT, user_agent);

    let inner = HttpClient::new(globals.runtime_handle.clone());

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
