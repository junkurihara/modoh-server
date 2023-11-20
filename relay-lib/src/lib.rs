mod constants;
mod count;
mod error;
mod globals;
mod hyper_body;
mod hyper_client;
mod hyper_executor;
mod log;
mod message_util;
mod relay;
mod router;
mod target;
mod validator;

use crate::{count::RequestCount, error::*, globals::Globals, log::*, router::Router};
use std::sync::Arc;

pub use auth_validator::{ValidationConfig, ValidationConfigInner};
pub use globals::{AccessConfig, ServiceConfig};

/// Entry point of the relay
pub async fn entrypoint(
  service_config: &ServiceConfig,
  runtime_handle: &tokio::runtime::Handle,
  term_notify: Option<Arc<tokio::sync::Notify>>,
) -> Result<()> {
  // build globals
  let globals = Arc::new(Globals {
    service_config: service_config.clone(),
    runtime_handle: runtime_handle.clone(),
    term_notify: term_notify.clone(),
    request_count: RequestCount::default(),
  });

  // build router
  let router = Router::try_new(&globals).await?;

  // start router
  if let Err(e) = router.start().await {
    warn!("(M)ODoH service stopped: {e}");
  }

  Ok(())
}
