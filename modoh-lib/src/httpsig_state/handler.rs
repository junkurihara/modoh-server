use super::HttpSigServiceState;
use crate::{error::*, globals::Globals, trace::*};
use futures::{select, FutureExt};
use httpsig_proto::HttpSigPublicKeys;
use std::sync::Arc;
use tokio::{sync::Notify, time::sleep};

/// HttpSig keys handler service that
/// - periodically refresh keys;
/// - periodically refetch configurations from other servers.
pub(crate) struct HttpSigKeysHandler {
  /// Service state
  state: Arc<HttpSigServiceState>,
}

impl HttpSigKeysHandler {
  /// Create a new HttpSigKeysRotator
  /// Fetch other servers' keys here first.
  pub(crate) async fn try_new(globals: &Arc<Globals>, state: &Arc<HttpSigServiceState>) -> Result<Arc<Self>> {
    let handler = Arc::new(Self { state: state.clone() });

    let handler_clone = handler.clone();
    let term_notify = globals.term_notify.clone();
    globals
      .runtime_handle
      .spawn(async move { handler_clone.start_httpsig_rotation(term_notify).await.ok() });

    Ok(handler)
  }

  /// Start the httpsig rotator
  async fn start_httpsig_rotation(&self, term_notify: Option<Arc<Notify>>) -> Result<()> {
    info!("Start httpsig config rotation service");

    match term_notify {
      Some(term) => loop {
        select! {
          _ = self.update_httpsig_configs().fuse() => {
            warn!("HTTP message signature config rotation service got down.");
          }
          _ = term.notified().fuse() => {
            info!("HTTP message signature config rotation service receives term signal");
            break;
          }
        }
      },
      None => {
        self.update_httpsig_configs().await?;
        warn!("HTTP message signature config rotation service got down.");
      }
    }
    Ok(())
  }

  /// Update httpsig config
  async fn update_httpsig_configs(&self) -> Result<()> {
    loop {
      sleep(self.state.rotation_period).await;

      let Ok(httpsig_configs) = HttpSigPublicKeys::new(&self.state.key_types) else {
        error!("Failed to generate httpsig configs. Keep current config unchanged.");
        continue;
      };
      let mut lock = self.state.configs.write().await;
      *lock = httpsig_configs;
      drop(lock);
    }
  }
}
