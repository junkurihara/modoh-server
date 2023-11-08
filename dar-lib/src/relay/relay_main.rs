use super::socket::bind_tcp_socket;
use crate::{error::*, globals::Globals, log::*};
use hyper::{client::connect::Connect, server::conn::Http, service::service_fn, Body, Request};
use std::sync::Arc;
use tokio::runtime::Handle;

#[derive(Clone)]
pub struct LocalExecutor {
  runtime_handle: Handle,
}

impl LocalExecutor {
  fn new(runtime_handle: Handle) -> Self {
    LocalExecutor { runtime_handle }
  }
}

impl<F> hyper::rt::Executor<F> for LocalExecutor
where
  F: std::future::Future + Send + 'static,
  F::Output: Send,
{
  fn execute(&self, fut: F) {
    self.runtime_handle.spawn(fut);
  }
}

/// (M)ODoH Relay object
pub struct Relay {
  pub globals: Arc<Globals>,
}

impl Relay {
  /// Start relay service
  pub async fn start_relay_service(&self, server: Http<LocalExecutor>) -> Result<()> {
    let listener_service = async {
      let tcp_socket = bind_tcp_socket(&self.globals.relay_config.listener_socket)?;
      let tcp_listener = tcp_socket.listen(self.globals.relay_config.tcp_listen_backlog)?;
      info!("Start TCP listener serving with HTTP request for configured host names");
      //   while let Ok((stream, _client_addr)) = tcp_listener.accept().await {
      //     self.clone().client_serve(stream, server.clone(), _client_addr, None);
      // }
      Ok(()) as Result<()>
    };
    listener_service.await?;
    Ok(())
  }

  /// Entrypoint for HTTP/1.1 and HTTP/2 servers
  pub async fn start(&self) -> Result<()> {
    info!("Start (M)ODoH relay");

    let mut server = Http::new();
    server.http1_keep_alive(self.globals.relay_config.keepalive);
    server.http2_max_concurrent_streams(self.globals.relay_config.max_concurrent_streams);
    server.pipeline_flush(true);
    let executor = LocalExecutor::new(self.globals.runtime_handle.clone());
    let server = server.with_executor(executor);

    match &self.globals.term_notify {
      Some(term) => {
        tokio::select! {
          _ = self.start_relay_service(server) => {
            warn!("Relay service got down");
          }
          _ = term.notified() => {
            info!("Relay service receives term signal");
          }
        }
      }
      None => {
        self.start_relay_service(server).await?;
        warn!("Relay service got down");
      }
    }
    Ok(())
  }
}
