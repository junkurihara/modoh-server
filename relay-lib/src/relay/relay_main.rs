use super::{count::RequestCount, forwarder::InnerForwarder, socket::bind_tcp_socket};
use crate::{
  error::*,
  globals::Globals,
  hyper_body::{passthrough_response, synthetic_error_response, EitherBody},
  hyper_executor::LocalExecutor,
  log::*,
  validator::Validator,
};
use hyper::{
  body::Incoming,
  header,
  rt::{Read, Write},
  service::service_fn,
  Request, StatusCode,
};
use hyper_tls::HttpsConnector;
use hyper_util::{
  client::legacy::connect::{Connect, HttpConnector},
  rt::TokioIo,
  server::{self, conn::auto::Builder as ConnectionBuilder},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::timeout;

/// (M)ODoH Relay main object
pub struct Relay<C>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  /// global config
  globals: Arc<Globals>,
  /// hyper server receiving http request
  http_server: Arc<ConnectionBuilder<LocalExecutor>>,
  /// hyper client forwarding requests to upstream
  inner_forwarder: Arc<InnerForwarder<C>>,
  /// validator for token validation
  inner_validator: Option<Arc<Validator<C>>>,
  /// request count
  request_count: RequestCount,
}

/// Service wrapper with validation
pub async fn serve_request_with_validation<C>(
  req: Request<Incoming>,
  peer_addr: SocketAddr,
  // forwarder: Arc<InnerForwarder<C, B>>,
  forwarder: Arc<InnerForwarder<C>>,
  validator: Option<Arc<Validator<C>>>,
) -> Result<hyper::Response<EitherBody>>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  // validation with header
  let mut validation_passed = false;
  if let (Some(validator), true) = (validator, req.headers().contains_key(header::AUTHORIZATION)) {
    debug!("execute token validation");
    let claims = match validator.validate_request(&req).await {
      Ok(claims) => {
        validation_passed = true;
        claims
      }
      Err(e) => {
        warn!("token validation failed: {}", e);
        return synthetic_error_response(StatusCode::from(e));
      }
    };
    debug!(
      "token validation passed: subject {}",
      claims.subject.as_deref().unwrap_or("")
    );
  }
  // TODO: IP addr check here? domain check should be done in forwarder

  // serve query as relay
  let res = match forwarder.serve(req, peer_addr, validation_passed).await {
    Ok(res) => passthrough_response(res),
    Err(e) => synthetic_error_response(StatusCode::from(e)),
  };
  debug!("serve query finish");
  res
}

impl<C> Relay<C>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  /// Serve tcp stream
  fn serve_connection<I>(&self, stream: I, peer_addr: SocketAddr)
  where
    I: Read + Write + Unpin + Send + 'static,
  {
    let request_count = self.request_count.clone();
    if request_count.increment() > self.globals.relay_config.max_clients {
      request_count.decrement();
      return;
    }
    debug!("Request incoming: current # {}", request_count.current());

    let server_clone = self.http_server.clone();
    let forwarder_clone = self.inner_forwarder.clone();
    let validator_clone = self.inner_validator.clone();
    let timeout_sec = self.globals.relay_config.timeout;
    self.globals.runtime_handle.clone().spawn(async move {
      timeout(
        timeout_sec + Duration::from_secs(1),
        server_clone.serve_connection(
          stream,
          service_fn(move |req: Request<Incoming>| {
            serve_request_with_validation(req, peer_addr, forwarder_clone.clone(), validator_clone.clone())
          }),
        ),
      )
      .await
      .ok();

      request_count.decrement();
      debug!("Request processed: current # {}", request_count.current());
    });
  }

  /// Start relay service
  async fn relay_service(&self) -> Result<()> {
    let listener_service = async {
      let tcp_socket = bind_tcp_socket(&self.globals.relay_config.listener_socket)?;
      let tcp_listener = tcp_socket.listen(self.globals.relay_config.tcp_listen_backlog)?;
      info!("Start TCP listener serving with HTTP request for configured host names");
      while let Ok((stream, peer_addr)) = tcp_listener.accept().await {
        self.serve_connection(TokioIo::new(stream), peer_addr);
      }
      Ok(()) as Result<()>
    };
    listener_service.await?;
    Ok(())
  }

  /// Start jwks retrieval service
  async fn jwks_service(&self) -> Result<()> {
    let Some(validator) = self.inner_validator.as_ref() else {
      return Err(RelayError::NoValidator);
    };
    validator.start_service(self.globals.term_notify.clone()).await
  }

  /// Entrypoint for HTTP/1.1 and HTTP/2 servers
  pub async fn start(&self) -> Result<()> {
    info!("Start (M)ODoH relay");

    // spawn jwks retrieval service if needed
    let services = async {
      if self.inner_validator.is_some() {
        tokio::select! {
          _ = self.jwks_service() => {
            warn!("jwks service got down");
          }
          _ = self.relay_service() => {
            warn!("Relay service got down");
          }
        }
      } else {
        self.relay_service().await.ok();
        warn!("Relay service got down")
      }
    };

    match &self.globals.term_notify {
      Some(term) => {
        tokio::select! {
          _ = services => {
            warn!("Relay service got down");
          }
          _ = term.notified() => {
            info!("Relay service receives term signal");
          }
        }
      }
      None => {
        services.await;
        warn!("Relay service got down");
      }
    }
    Ok(())
  }
}

impl Relay<HttpsConnector<HttpConnector>> {
  /// build relay
  pub async fn try_new(globals: &Arc<Globals>) -> Result<Self> {
    let executor = LocalExecutor::new(globals.runtime_handle.clone());
    let mut server = server::conn::auto::Builder::new(executor);
    server
      .http1()
      .keep_alive(globals.relay_config.keepalive)
      .pipeline_flush(true);
    server
      .http2()
      .max_concurrent_streams(globals.relay_config.max_concurrent_streams);

    let http_server = Arc::new(server);
    let inner_forwarder = Arc::new(InnerForwarder::try_new(globals)?);
    let inner_validator = match globals.relay_config.validation.as_ref() {
      Some(v) => Some(Arc::new(Validator::try_new(v, globals.runtime_handle.clone()).await?)),
      None => None,
    };

    Ok(Self {
      globals: globals.clone(),
      http_server,
      inner_forwarder,
      inner_validator,
      request_count: RequestCount::default(),
    })
  }
}
