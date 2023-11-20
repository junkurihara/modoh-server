use super::odoh::ODoHPublicKey;
use crate::{
  constants::{ODOH_CONFIGS_PATH, ODOH_KEY_ROTATION_SECS, STALE_IF_ERROR_SECS, STALE_WHILE_REVALIDATE_SECS},
  count::RequestCount,
  error::*,
  globals::Globals,
  hyper_body::{full, BoxBody},
  log::*,
  message_util::inspect_host,
};
use futures::{select, FutureExt};
use http::{header, Method, Request, Response};
use hyper::body::Bytes;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
  sync::{Notify, RwLock},
  time::sleep,
};

/// build http response from given packet
pub(super) fn build_http_response(
  packet: &[u8],
  ttl: u64,
  content_type: &str,
  cors: bool,
) -> HttpResult<Response<BoxBody>> {
  let packet_len = packet.len();
  let mut response_builder = Response::builder()
    .header(header::CONTENT_LENGTH, packet_len)
    .header(header::CONTENT_TYPE, content_type)
    .header(
      header::CACHE_CONTROL,
      format!(
        "max-age={ttl}, stale-if-error={STALE_IF_ERROR_SECS}, stale-while-revalidate={STALE_WHILE_REVALIDATE_SECS}"
      )
      .as_str(),
    );
  if cors {
    response_builder = response_builder.header(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
  }
  let body = full(Bytes::copy_from_slice(packet));
  response_builder.body(body).map_err(|_| HttpError::InvalidODoHConfig)
}

/// wrapper of dns forwarder
pub struct InnerTarget {
  /// target host name
  pub(super) target_host: String,
  /// url path listening for odoh query
  pub(crate) target_path: String,
  /// local bind address to listen udp packet
  pub(super) local_bind_address: SocketAddr,
  /// upstream dns server address
  pub(super) upstream: SocketAddr,
  /// TTL for errors, in seconds
  pub(super) err_ttl: u32,
  /// Maximum TTL, in seconds
  pub(super) max_ttl: u32,
  /// Minimum TTL, in seconds
  pub(super) min_ttl: u32,
  /// ODOh config path
  pub(crate) odoh_configs_path: String,
  /// ODoH configs periodically rotated
  pub(super) odoh_configs: Arc<RwLock<ODoHPublicKey>>,
  /// timeout for dns query
  pub(super) timeout: Duration,
  /// Maximum number of TCP session including HTTP request from clients
  pub(super) max_tcp_sessions: usize,
  /// HTTP request count under the service to count tcp sessions
  pub(super) request_count: RequestCount,
}

impl InnerTarget {
  /// Serve odoh config via GET method
  pub async fn serve_odoh_configs<B>(&self, req: Request<B>) -> HttpResult<Response<BoxBody>> {
    // check host
    inspect_host(&req, &self.target_host)?;
    // check path
    if req.uri().path() != self.odoh_configs_path {
      return Err(HttpError::InvalidPath);
    };
    // check method, only get method is allowed for odoh config
    if req.method() != Method::GET {
      return Err(HttpError::InvalidMethod);
    };

    let lock = self.odoh_configs.read().await;
    let configs = lock.as_config().to_owned();
    drop(lock);
    build_http_response(&configs, ODOH_KEY_ROTATION_SECS, "application/octet-stream", true)
  }

  /// Start odoh config rotation service
  async fn start_odoh_rotation(&self, term_notify: Option<Arc<Notify>>) -> Result<()> {
    info!("Start odoh config rotation service");

    match term_notify {
      Some(term) => loop {
        select! {
          _ = self.update_odoh_configs().fuse() => {
            warn!("ODoH config rotation service got down.");
          }
          _ = term.notified().fuse() => {
            info!("ODoH config rotation service receives term signal");
            break;
          }
        }
      },
      None => {
        self.update_odoh_configs().await?;
        warn!("ODoH config rotation service got down.");
      }
    }
    Ok(())
  }
  /// Update odoh config
  async fn update_odoh_configs(&self) -> Result<()> {
    loop {
      sleep(Duration::from_secs(ODOH_KEY_ROTATION_SECS)).await;

      let Ok(odoh_configs) = ODoHPublicKey::new() else {
        error!("Failed to generate odoh configs. Keep current config unchanged.");
        continue;
      };
      let mut lock = self.odoh_configs.write().await;
      *lock = odoh_configs;
      drop(lock);
    }
  }

  /// Build inner relay
  pub fn try_new(globals: &Arc<Globals>) -> Result<Arc<Self>> {
    let target_config = globals
      .service_config
      .target
      .as_ref()
      .ok_or(MODoHError::BuildTargetError)?;
    let target_host = globals.service_config.hostname.clone();
    let target_path = target_config.path.clone();
    let upstream = target_config.upstream;
    let local_bind_address = target_config.local_bind_address;
    let error_ttl = target_config.error_ttl;
    let max_ttl = target_config.max_ttl;
    let min_ttl = target_config.min_ttl;
    let odoh_configs_path = ODOH_CONFIGS_PATH.to_string();
    let odoh_configs = Arc::new(RwLock::new(ODoHPublicKey::new()?));
    let timeout = globals.service_config.timeout;
    let max_tcp_sessions = globals.service_config.max_clients;
    let request_count = globals.request_count.clone();

    let target = Arc::new(Self {
      target_host,
      target_path,
      upstream,
      local_bind_address,
      err_ttl: error_ttl,
      max_ttl,
      min_ttl,
      odoh_configs_path,
      odoh_configs,
      timeout,
      max_tcp_sessions,
      request_count,
    });

    let target_clone = target.clone();
    let term_notify = globals.term_notify.clone();
    globals
      .runtime_handle
      .spawn(async move { target_clone.start_odoh_rotation(term_notify).await.ok() });

    Ok(target)
  }
}
