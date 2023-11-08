mod auth;
mod constants;
mod error;
mod globals;
mod log;
mod relay;

use crate::{error::*, globals::Globals, log::*, relay::Relay};
use std::sync::Arc;

pub use {
  auth::ValidationKey,
  globals::{AuthConfig, IpAndDomainConfig, RelayConfig, TokenConfig},
};

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
  let relay = Relay::try_new(&globals)?;

  // start relay
  if let Some(term_notify) = term_notify {
    tokio::select! {
      _ = relay.start() => {
        // relay stopped
        warn!("(M)ODoH relay stopped.");
      }
      _ = term_notify.notified() => {
        // relay stopped
        warn!("Terminate signal received.");
      }
    }
  } else {
    relay.start().await?;
  }

  Ok(())
}
