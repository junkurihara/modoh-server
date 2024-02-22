use super::{router_serve_req::serve_request_with_validation, socket::bind_tcp_socket};
use crate::{
  count::RequestCount, error::*, globals::Globals, hyper_client::HttpClient, hyper_executor::LocalExecutor, relay::InnerRelay,
  request_filter::RequestFilter, target::InnerTarget, trace::*, validator::Validator,
};
use hyper::{
  body::Incoming,
  rt::{Read, Write},
  service::service_fn,
  Request,
};
use hyper_util::{client::legacy::connect::Connect, rt::TokioIo, server::conn::auto::Builder as ConnectionBuilder};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::timeout;
use tracing::Instrument as _;

#[derive(Clone)]
/// (M)ODoH Router main object
pub struct Router<C>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  /// global config
  pub(crate) globals: Arc<Globals>,
  /// hyper server receiving http request
  pub(crate) http_server: Arc<ConnectionBuilder<LocalExecutor>>,
  /// hyper client forwarding requests to upstream
  pub(crate) inner_relay: Option<Arc<InnerRelay<C>>>,
  /// dns client forwarding dns query to upstream
  pub(crate) inner_target: Option<Arc<InnerTarget>>, // TODO: add httpsigconfigs endpoint to inner_target
  /// validator for token validation
  pub(crate) inner_validator: Option<Arc<Validator<C>>>,
  /// request count
  pub(crate) request_count: RequestCount,
  /// request filter
  pub(crate) request_filter: Option<Arc<RequestFilter>>,
  // TODO: httpsig_verifier
}

impl<C> Router<C>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  /// Serve tcp stream
  fn serve_connection<I>(&self, stream: I, peer_addr: SocketAddr)
  where
    I: Read + Write + Unpin + Send + 'static,
  {
    let request_count = self.request_count.clone();
    if request_count.increment() > self.globals.service_config.max_clients as isize {
      request_count.decrement();
      return;
    }
    debug!("Request incoming: current # {}", request_count.current());

    let self_clone = self.clone();
    let server_clone = self.http_server.clone();
    let timeout_sec = self.globals.service_config.timeout;
    self.globals.runtime_handle.clone().spawn(async move {
      timeout(
        // This timeout is for the whole request. Add 1 sec for safety.
        // For each services, i.e., relay, target, etc., shorter timeout is set.
        timeout_sec + Duration::from_secs(1),
        server_clone.serve_connection(
          stream,
          service_fn(move |req: Request<Incoming>| {
            let current_span = tracing::info_span!("router_serve", method = ?req.method(), uri = ?req.uri(), peer_addr = ?peer_addr, xff = ?req.headers().get("x-forwarded-for"), forwarded = ?req.headers().get("forwarded"), traceparent = ?req.headers().get("traceparent"));

            #[cfg(feature = "evil-trace")]
            {
              use opentelemetry::{Context, trace::TraceContextExt};
              use tracing_opentelemetry::OpenTelemetrySpanExt;
              let span_cx = crate::evil_trace::get_span_cx_from_request(&req);
              if span_cx.is_some() {
                let span_cx = span_cx.unwrap();
                debug!(trace_id = span_cx.trace_id().to_string(), parent_span_id = span_cx.span_id().to_string(), "evil-trace enabled. received traceparent header.");
                let context = Context::new().with_remote_span_context(span_cx);
                current_span.set_parent(context);
                current_span.context().span().span_context().trace_id();
                debug!(trace_id = current_span.context().span().span_context().trace_id().to_string(), child_span_id = current_span.context().span().span_context().span_id().to_string(), "evil-trace enabled. get into child span");
              }
            }
            serve_request_with_validation(req, peer_addr, self_clone.clone()).instrument(current_span)
    }),
        ),
      )
      .await
      .ok();

      request_count.decrement();
      debug!("Request processed: current # {}", request_count.current());
    });
  }

  /// Start http routing service
  async fn router_service(&self) -> Result<()> {
    let listener_service = async {
      let tcp_socket = bind_tcp_socket(&self.globals.service_config.listener_socket)?;
      let tcp_listener = tcp_socket.listen(self.globals.service_config.tcp_listen_backlog)?;
      info!("Start TCP listener serving with HTTP request for configured host names");
      while let Ok((stream, peer_addr)) = tcp_listener.accept().await {
        self.serve_connection(TokioIo::new(stream), peer_addr);
      }
      Ok(()) as Result<()>
    };
    listener_service.await?;
    Ok(())
  }

  /// Entrypoint for HTTP/1.1 and HTTP/2 servers
  pub async fn start(&self) -> Result<()> {
    info!("Start (M)ODoH services");

    match &self.globals.term_notify {
      Some(term) => {
        tokio::select! {
          _ = self.router_service() => {
            warn!("Http routing service got down");
          }
          _ = term.notified() => {
            info!("Http routing service receives term signal");
          }
        }
      }
      None => {
        self.router_service().await.ok();
        warn!("Http routing service got down");
      }
    }
    Ok(())
  }

  /// build router
  pub async fn try_new(
    globals: &Arc<Globals>,
    http_server: &Arc<ConnectionBuilder<LocalExecutor>>,
    http_client: &Arc<HttpClient<C>>,
  ) -> Result<Self> {
    let request_count = globals.request_count.clone();

    let inner_validator = match globals.service_config.validation.as_ref() {
      Some(_) => Some(Validator::try_new(globals, http_client).await?),
      None => None,
    };
    let request_filter = globals
      .service_config
      .access
      .as_ref()
      .map(|_| Arc::new(RequestFilter::new(globals.service_config.access.as_ref().unwrap())));

    // TODO: build httpsig rotation and verifier service struct

    let inner_relay = match &globals.service_config.relay {
      Some(_) => Some(InnerRelay::try_new(globals, http_client, request_filter.clone())?),
      None => None,
    };
    let inner_target = match &globals.service_config.target {
      Some(_) => Some(InnerTarget::try_new(globals)?),
      None => None,
    };

    Ok(Self {
      globals: globals.clone(),
      http_server: http_server.clone(),
      inner_relay,
      inner_target,
      inner_validator,
      request_count,
      request_filter,
    })
  }
}
