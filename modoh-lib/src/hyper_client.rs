use crate::{error::*, hyper_executor::LocalExecutor};
use http::{Request, Response};
use hyper::body::{Body, Incoming};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::{
  connect::{Connect, HttpConnector},
  Client,
};

#[derive(Clone)]
/// Http client that is used for forwarding requests to upstream and fetching jwks from auth server.
pub struct HttpClient<C, B>
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
  /// wrapper request fn
  pub async fn request(
    &self,
    req: Request<B>,
  ) -> std::result::Result<Response<Incoming>, hyper_util::client::legacy::Error> {
    self.inner.request(req).await
  }
}

impl<B> HttpClient<HttpsConnector<HttpConnector>, B>
where
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
  /// Build inner client with hyper-tls
  pub fn try_new(runtime_handle: tokio::runtime::Handle) -> Result<Self> {
    // build hyper client with hyper-tls, only https is allowed
    let alpns = &["h2", "http/1.1"];
    let mut connector = hyper_tls::native_tls::TlsConnector::builder()
      .request_alpns(alpns)
      .build()
      .map_err(|e| MODoHError::FailedToBuildHttpClient(e.to_string()))
      .map(|tls| {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        HttpsConnector::from((http, tls.into()))
      })?;
    connector.https_only(true);
    let executor = LocalExecutor::new(runtime_handle.clone());
    let inner = Client::builder(executor).build::<_, B>(connector);

    // build hyper client with rustls and webpki, only https is allowed
    // let connector = hyper_rustls::HttpsConnectorBuilder::new()
    //   .with_webpki_roots()
    //   .https_only()
    //   .enable_http1()
    //   .enable_http2()
    //   .build();
    // let inner = Client::builder(TokioExecutor::new()).build::<_, B>(connector);

    Ok(Self { inner })
  }
}
