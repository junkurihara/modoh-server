mod constants;
mod error;
mod globals;
mod log;
mod relay;
mod validation;

use crate::{error::*, globals::Globals, log::*, relay::Relay, validation::TokenValidator};
use futures::future::select_all;
use std::sync::Arc;

pub use globals::{AccessConfig, RelayConfig, TokenConfigInner, ValidationConfig};

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

  // spawn jwks retrieval service if needed
  let mut validator = None;
  let mut auth_service = None;
  if let Some(auth) = relay_config.validation.as_ref() {
    let validator_inner = Arc::new(TokenValidator::try_from(auth)?);
    let validator_inner_clone = validator_inner.clone();
    let term_notify = term_notify.clone();
    let service_inner = runtime_handle.spawn(async move {
      if let Err(e) = validator_inner.start_service(term_notify).await {
        error!("jwks refresh service got down: {}", e);
      }
    });
    validator = Some(validator_inner_clone);
    auth_service = Some(service_inner);
  }

  // build relay
  let relay = Relay::try_new(&globals, &validator)?;

  // start relay
  let relay_service = runtime_handle.spawn(async move {
    if let Err(e) = relay.start().await {
      warn!("(M)ODoH relay stopped: {e}");
    }
  });

  if let Some(auth_service) = auth_service {
    let _ = select_all(vec![relay_service, auth_service]).await;
  } else {
    let _ = relay_service.await;
  }

  Ok(())
}
