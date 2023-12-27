use crate::{
  error::*,
  hyper_body::{BoxBody, IncomingOr},
  hyper_executor::LocalExecutor,
  trace::*,
};
use http::{Request, Response};
use hyper::body::{Body, Incoming};
use hyper_util::client::legacy::{
  connect::{Connect, HttpConnector},
  Client,
};
use tracing::instrument;

#[derive(Clone)]
/// Http client that is used for forwarding requests to upstream and fetching jwks from auth server.
pub struct HttpClient<C, B = IncomingOr<BoxBody>>
where
  C: Send + Sync + Connect + Clone + 'static,
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
  pub inner: Client<C, B>,
}

impl<C, B> HttpClient<C, B>
where
  C: Send + Sync + Connect + Clone + 'static,
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
  #[instrument(level = "debug", name = "http_request", skip_all)]
  /// wrapper request fn
  pub async fn request(
    &self,
    req: Request<B>,
  ) -> std::result::Result<Response<Incoming>, hyper_util::client::legacy::Error> {
    #[cfg(feature = "evil-trace")]
    {
      use crate::constants::{EVIL_TRACE_FLAGS, EVIL_TRACE_HEADER_NAME, EVIL_TRACE_VERSION};
      use opentelemetry::trace::TraceContextExt;
      use tracing_opentelemetry::OpenTelemetrySpanExt;
      let current_span_context = tracing::Span::current().context().span().span_context().clone();
      let header_value = format!(
        "{}-{}-{}-{}",
        EVIL_TRACE_VERSION,
        current_span_context.trace_id(),
        current_span_context.span_id(),
        EVIL_TRACE_FLAGS
      );
      let mut req = req;
      let headers = req.headers_mut();
      headers.insert(
        http::HeaderName::from_static(EVIL_TRACE_HEADER_NAME),
        http::HeaderValue::from_str(&header_value).unwrap_or(http::HeaderValue::from_static("")),
      );
      debug!("evil-trace enabled. header: {:?}", req.headers());
      self.inner.request(req).await
    }

    #[cfg(not(feature = "evil-trace"))]
    self.inner.request(req).await
  }
}

#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
impl<B> HttpClient<HttpConnector, B>
where
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
  /// Build inner client with http
  pub fn try_new(runtime_handle: tokio::runtime::Handle) -> Result<Self> {
    warn!(
      "
--------------------------------------------------------------------------------------------------
(M)ODoH relay and jwks client running without TLS support!!!
This may not be able to not only forward queries to upstream but also fetch jwks from auth server.
Use this just for testing. Please enable native-tls or rustls feature to enable TLS support.
--------------------------------------------------------------------------------------------------"
    );
    let executor = LocalExecutor::new(runtime_handle.clone());
    let mut http = HttpConnector::new();
    http.set_reuse_address(true);
    let inner = Client::builder(executor).build::<_, B>(http);
    Ok(Self { inner })
  }
}

#[cfg(all(feature = "native-tls", not(feature = "rustls")))]
impl<B> HttpClient<hyper_tls::HttpsConnector<HttpConnector>, B>
where
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
  /// Build inner client with hyper-tls
  pub fn try_new(runtime_handle: tokio::runtime::Handle) -> Result<Self> {
    // build hyper client with hyper-tls, only https is allowed
    info!("Native TLS support is enabled for (M)ODoH forwarder");
    let alpns = &["h2", "http/1.1"];
    let connector = hyper_tls::native_tls::TlsConnector::builder()
      .request_alpns(alpns)
      .build()
      .map_err(|e| MODoHError::FailedToBuildHttpClient(e.to_string()))
      .map(|tls| {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_reuse_address(true);
        hyper_tls::HttpsConnector::from((http, tls.into()))
      })?;
    let executor = LocalExecutor::new(runtime_handle.clone());
    let inner = Client::builder(executor).build::<_, B>(connector);

    Ok(Self { inner })
  }
}

#[cfg(feature = "rustls")]
/// Build forwarder with hyper-rustls (rustls)
impl<B> HttpClient<hyper_tls::HttpsConnector<HttpConnector>, B>
where
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
  /// Build forwarder
  pub fn try_new(runtime_handle: tokio::runtime::Handle) -> Result<Self> {
    todo!("Not implemented yet. Please use native-tls-backend feature for now.");

    // build hyper client with rustls and webpki, only https is allowed
    // let connector = hyper_rustls::HttpsConnectorBuilder::new()
    //   .with_webpki_roots()
    //   .https_only()
    //   .enable_http1()
    //   .enable_http2()
    //   .build();
    // let inner = Client::builder(TokioExecutor::new()).build::<_, B>(connector);
  }
}
