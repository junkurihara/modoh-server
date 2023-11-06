mod globals;
mod error;
mod constants;
mod auth;

use std::sync::Arc;
use crate::error::*;

pub use {globals::{RelayConfig, AuthConfig, TokenConfig, IpAndDomainConfig}, auth::ValidationKey};

pub async fn entrypoint(
  relay_config: &RelayConfig,
  runtime_handle: &tokio::runtime::Handle,
  term_notify: Option<Arc<tokio::sync::Notify>>,
) -> Result<()> {
  println!("Hello, world!");
  Ok(())
}
