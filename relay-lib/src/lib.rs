mod constants;
mod error;
mod globals;
mod http_client;
mod hyper_executor;
mod log;
mod relay;
mod validator;

use crate::{error::*, globals::Globals, log::*, relay::Relay};
use std::sync::Arc;

pub use auth_validator::{ValidationConfig, ValidationConfigInner};
pub use globals::{AccessConfig, RelayConfig};

/// Entry point of the relay
pub async fn entrypoint(
  relay_config: &RelayConfig,
  runtime_handle: &tokio::runtime::Handle,
  term_notify: Option<Arc<tokio::sync::Notify>>,
) -> Result<()> {
  // build globals
  let globals = Arc::new(Globals {
    relay_config: relay_config.clone(),
    runtime_handle: runtime_handle.clone(),
    term_notify: term_notify.clone(),
  });

  // build relay
  let relay = Relay::try_new(&globals).await?;

  // start relay
  if let Err(e) = relay.start().await {
    warn!("(M)ODoH relay stopped: {e}");
  }

  Ok(())
}
