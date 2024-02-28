use super::HttpSigSelfKeyState;
use crate::{
  constants::{HTTPSIG_KEY_REFETCH_TIMEOUT_SEC, HTTPSIG_REFETCH_USER_AGENT},
  error::*,
  globals::{Globals, HttpSigDomainInfo},
  hyper_body::{BoxBody, IncomingOr},
  hyper_client::HttpClient,
  trace::*,
};
use futures::{select, FutureExt};
use http::{header, Method, Request};
use http_body_util::{BodyExt, Empty};
use httpsig_proto::{Deserialize, HttpSigConfigContents, HttpSigConfigs, HttpSigPublicKeys};
use hyper::body::{Body, Bytes};
use hyper_util::client::legacy::connect::Connect;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Notify, time::sleep};

/// HttpSig keys handler service that
/// - periodically refresh keys;
/// - periodically refetch configurations from other servers.
pub(crate) struct HttpSigKeysHandler<C, B = IncomingOr<BoxBody>>
where
  C: Send + Sync + Connect + Clone + 'static,
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
  /// hyper client
  pub http_client: Arc<HttpClient<C, B>>,
  /// Service state for exposed httpsig public keys
  state: Arc<HttpSigSelfKeyState>,

  /// Public key fetcher target domains
  targets_info: Vec<HttpSigDomainInfo>,
  // TODO: add inner state and data structure updated by fetcher and used by router, target, relay
  /// Public key refetch period
  refetch_period: Duration,
}

impl<C> HttpSigKeysHandler<C>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  /// Create a new HttpSigKeysRotator
  /// Fetch other servers' keys here first.
  pub(crate) async fn try_new(
    globals: &Arc<Globals>,
    http_client: &Arc<HttpClient<C>>,
    state: &Arc<HttpSigSelfKeyState>,
  ) -> Result<Arc<Self>> {
    let httpsig_config = globals
      .service_config
      .access
      .as_ref()
      .ok_or(MODoHError::BuildHttpSigHandlerError)?
      .httpsig
      .as_ref()
      .ok_or(MODoHError::BuildHttpSigHandlerError)?;
    let targets_info = httpsig_config.enabled_domains.clone();
    let refetch_period = httpsig_config.refetch_period;

    let handler = Arc::new(Self {
      state: state.clone(),
      refetch_period,
      targets_info,
      http_client: http_client.clone(),
    });

    // rotator for httpsig key pairs
    let handler_clone = handler.clone();
    let term_notify = globals.term_notify.clone();
    globals
      .runtime_handle
      .spawn(async move { handler_clone.start_httpsig_rotation(term_notify).await.ok() });

    // periodic fetcher for httpsig public keys
    let handler_clone = handler.clone();
    let term_notify = globals.term_notify.clone();
    globals
      .runtime_handle
      .spawn(async move { handler_clone.start_httpsig_pk_fetcher_service(term_notify).await.ok() });

    Ok(handler)
  }

  /// Start the rotator for httpsig key pairs,
  /// where public keys are exposed at /.well-known/httpsigconfigs
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

  /// Start the periodic fetcher for httpsig public keys,
  async fn start_httpsig_pk_fetcher_service(&self, term_notify: Option<Arc<Notify>>) -> Result<()> {
    info!("Start external httpsig config fetcher service");

    match term_notify {
      Some(term) => loop {
        select! {
          _ = self.fetch_and_handle_httpsig_public_keys().fuse() => {
            warn!("Fetcher service for HTTP message signature config got down.");
          }
          _ = term.notified().fuse() => {
            info!("Fetcher service for HTTP message signature config receives term signal");
            break;
          }
        }
      },
      None => {
        self.fetch_and_handle_httpsig_public_keys().await?;
        warn!("Fetcher service for HTTP message signature config got down.");
      }
    }
    Ok(())
  }
  /// Fetch httpsig public keys from other servers
  /// If public keys for DH are included in fetched configs, derive shared secret keys as well.
  async fn fetch_and_handle_httpsig_public_keys(&self) -> Result<()> {
    loop {
      let futures = self.targets_info.iter().map(|info| async {
        let config_endpoint_uri = info.configs_endpoint_uri.clone();
        let deserialized_configs = self.fetch_and_deserialize(&config_endpoint_uri).await?;
        Ok(deserialized_configs) as Result<_>
      });
      let all_deserialized_configs = futures::future::join_all(futures).await;
      let _with_info = all_deserialized_configs
        .iter()
        .zip(self.targets_info.iter())
        .collect::<Vec<_>>();
      // TODO: Analyze and store the fetched configs
      // TODO:
      // TODO:

      sleep(self.refetch_period).await;
    }
  }

  /// Fetch and deserialize httpsig public keys from a given endpoint uri,
  /// Vec<HttpSigConfigContents> object is retrieved for the endpoint
  async fn fetch_and_deserialize(&self, uri: &http::Uri) -> Result<Vec<HttpSigConfigContents>> {
    debug!("Fetching httpsig public keys from {}", uri);

    let request = Request::builder()
      .uri(uri)
      .method(Method::GET)
      .header(
        header::USER_AGENT,
        header::HeaderValue::from_static(HTTPSIG_REFETCH_USER_AGENT),
      )
      .body(Empty::<Bytes>::new().map_err(|never| match never {}).boxed())
      .map_err(|e| {
        error!("Failed to build request for fetching httpsig public keys: {}", e);
        MODoHError::FetchHttpsigConfigsError(e.to_string())
      })?;
    let response_future = tokio::time::timeout(
      Duration::from_secs(HTTPSIG_KEY_REFETCH_TIMEOUT_SEC),
      self.http_client.request(request.map(IncomingOr::Right)),
    );
    let response = response_future
      .await
      .map_err(|e| {
        error!("Timeout to fetch httpsig public keys: {}", e);
        MODoHError::FetchHttpsigConfigsError(e.to_string())
      })?
      .map_err(|e| {
        error!("Failed to fetch httpsig public keys: {}", e);
        MODoHError::FetchHttpsigConfigsError(e.to_string())
      })?;
    let body_bytes = response
      .into_body()
      .collect()
      .await
      .map_err(|e| {
        error!("Failed to read httpsig public keys response body: {}", e);
        MODoHError::FetchHttpsigConfigsError(e.to_string())
      })?
      .to_bytes();
    let deserialized_configs = HttpSigConfigs::deserialize(&mut body_bytes.as_ref())?;
    let deserialized_configs = deserialized_configs.into_iter().map(|config| config.contents).collect();
    info!("Fetched httpsig public keys from {}:\n{:#?}", uri, deserialized_configs);
    Ok(deserialized_configs)
  }
}
