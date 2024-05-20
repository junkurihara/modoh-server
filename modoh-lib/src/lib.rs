mod constants;
mod count;
mod dns;
mod error;
mod globals;
mod httpsig_handler;
mod hyper_body;
mod hyper_client;
mod hyper_executor;
mod message_util;
mod relay;
mod request_filter;
mod router;
mod target;
mod trace;
mod validator;

#[cfg(feature = "metrics")]
mod metrics;

#[cfg(feature = "evil-trace")]
mod evil_trace;

use crate::{count::RequestCount, error::*, globals::Globals, router::Router, trace::*};
use hyper_client::HttpClient;
use hyper_executor::LocalExecutor;
use hyper_util::server::{self, conn::auto::Builder as ConnectionBuilder};
use std::sync::Arc;

pub use auth_validator::{ValidationConfig, ValidationConfigInner};
pub use globals::{AccessConfig, HttpSigConfig, HttpSigDomain, HttpSigRegistry, ServiceConfig};

/// Entry point of the relay
pub async fn entrypoint(
  service_config: &ServiceConfig,
  runtime_handle: &tokio::runtime::Handle,
  term_notify: Option<Arc<tokio::sync::Notify>>,
) -> Result<()> {
  #[cfg(all(feature = "rustls", feature = "native-tls"))]
  warn!("Both \"native-tls\" and feature \"rustls\" features are enabled. \"rustls\" will be used.");

  #[cfg(feature = "metrics")]
  // build meters from global meters
  let meters = Arc::new(crate::metrics::Meters::new());

  #[cfg(feature = "qrlog")]
  // build qrlog logger
  let qrlog_tx = {
    let (tx, mut logger) = QrLogger::new(term_notify.clone());
    runtime_handle.spawn(async move {
      logger.start().await;
    });
    tx
  };

  // build globals
  let globals = Arc::new(Globals {
    service_config: service_config.clone(),
    runtime_handle: runtime_handle.clone(),
    term_notify: term_notify.clone(),
    request_count: RequestCount::default(),
    #[cfg(feature = "metrics")]
    meters,
    #[cfg(feature = "qrlog")]
    qrlog_tx,
  });
  // build http client
  let http_client = Arc::new(HttpClient::try_new(runtime_handle.clone())?);

  // build http_server which is used for router and prometheus
  let http_server = build_hyper_server(&globals);

  // build router
  let router = Router::try_new(&globals, &http_server, &http_client).await?;

  // start router
  if let Err(e) = router.start().await {
    warn!("(M)ODoH service stopped: {e}");
  }

  Ok(())
}

/// build hyper server
fn build_hyper_server(globals: &Arc<Globals>) -> Arc<ConnectionBuilder<LocalExecutor>> {
  let executor = LocalExecutor::new(globals.runtime_handle.clone());
  let mut server = server::conn::auto::Builder::new(executor);
  server
    .http1()
    .keep_alive(globals.service_config.keepalive)
    .pipeline_flush(true);
  server
    .http2()
    .max_concurrent_streams(globals.service_config.max_concurrent_streams);
  Arc::new(server)
}
