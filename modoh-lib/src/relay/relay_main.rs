use crate::{
  constants::*,
  error::*,
  globals::Globals,
  hyper_body::{BoxBody, IncomingOr},
  hyper_client::HttpClient,
  message_util::{check_content_type, inspect_host, inspect_request_body, RequestType},
  request_filter::RequestFilter,
  trace::*,
};
use http::{
  header::{self, HeaderMap, HeaderValue},
  request::Parts,
  Method, Request, Response,
};
use hyper::body::{Body, Incoming};
use hyper_util::client::legacy::connect::Connect;
use std::sync::Arc;
use url::Url;

/// wrapper of http client
pub struct InnerRelay<C, B = IncomingOr<BoxBody>>
where
  C: Send + Sync + Connect + Clone + 'static,
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
  /// hyper client
  pub(super) inner: Arc<HttpClient<C, B>>,
  /// request default headers
  pub(super) request_headers: HeaderMap,
  /// relay host name
  pub(super) relay_host: String,
  /// url path listening for odoh query
  pub(crate) relay_path: String,
  /// max number of subsequent nodes
  pub(super) max_subseq_nodes: usize,
  /// request filter for destination domain name
  pub(super) request_filter: Option<Arc<RequestFilter>>,
}

impl<C, B> InnerRelay<C, B>
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
  pub async fn serve(&self, req: Request<B>) -> HttpResult<Response<Incoming>> {
    // check host
    inspect_host(&req, &self.relay_host)?;

    // check path
    if req.uri().path() != self.relay_path {
      return Err(HttpError::InvalidPath);
    };
    // check method
    if req.method() != Method::POST {
      return Err(HttpError::InvalidMethod);
    };
    // check content type
    if check_content_type(&req)? != RequestType::ODoH {
      return Err(HttpError::UnsupportedRequestType);
    };

    // build next hop url
    let Ok(current_url) = &url::Url::parse(&format!(
      "https://{}{}",
      self.relay_host,
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

    // next hop domain name check here
    // for authorized domains, maintain blacklist (error metrics) at each relay for given responses
    let nexthop_domain = nexthop_url.host_str().ok_or(HttpError::InvalidUrl)?;
    let filter_result = self.request_filter.as_ref().and_then(|filter| {
      filter
        .outbound_filter
        .as_ref()
        .map(|outbound| outbound.in_domain_list(nexthop_domain))
    });
    if let Some(res) = filter_result {
      if !res {
        debug!("Nexthop domain is filtered: {}", nexthop_domain);
        return Err(HttpError::ForbiddenDomain(nexthop_domain.to_string()));
      }

      debug!("Passed destination domain access control");
    }

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
      return Err(HttpError::UnsupportedRequestType);
    };

    // update header
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(ODOH_CACHE_CONTROL));
    headers.insert("proxy-status", HeaderValue::from_str(proxy_status.as_str()).unwrap());
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));

    Ok(())
  }

  /// Build inner relay
  pub fn try_new(
    globals: &Arc<Globals>,
    http_client: &Arc<HttpClient<C, B>>,
    request_filter: Option<Arc<RequestFilter>>,
  ) -> Result<Arc<Self>> {
    let relay_config = globals
      .service_config
      .relay
      .as_ref()
      .ok_or(MODoHError::BuildRelayError)?;
    // default headers for request
    let mut request_headers = HeaderMap::new();
    let user_agent = HeaderValue::from_str(relay_config.http_user_agent.as_str()).map_err(|e| {
      error!("{e}");
      MODoHError::BuildRelayError
    })?;
    request_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(ODOH_CONTENT_TYPE));
    request_headers.insert(header::ACCEPT, HeaderValue::from_static(ODOH_CONTENT_TYPE));
    request_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(ODOH_CACHE_CONTROL));
    request_headers.insert(header::USER_AGENT, user_agent);

    let relay_host = globals.service_config.hostname.clone();
    let relay_path = relay_config.path.clone();
    let max_subseq_nodes = relay_config.max_subseq_nodes;

    Ok(Arc::new(Self {
      inner: http_client.clone(),
      request_headers,
      relay_host,
      relay_path,
      max_subseq_nodes,
      request_filter: request_filter.clone(),
    }))
  }
}
