use super::HttpSigKeysHandler;
use crate::{
  constants::{HTTPSIG_KEY_REFETCH_TIMEOUT_SEC, HTTPSIG_REFETCH_USER_AGENT},
  error::*,
  hyper_body::IncomingOr,
  hyper_client::HttpClient,
  trace::*,
};
use futures::{select, FutureExt};
use http::{header, Method, Request};
use http_body_util::{BodyExt, Empty};
use httpsig_proto::{Deserialize, HttpSigConfigContents, HttpSigConfigs, HttpSigPublicKeys};
use hyper::body::Bytes;
use hyper_util::client::legacy::connect::Connect;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Notify, time::sleep};

impl<C> HttpSigKeysHandler<C>
where
  C: Send + Sync + Connect + Clone + 'static,
{
  /// Start the rotator for httpsig key pairs,
  /// where public keys are exposed at /.well-known/httpsigconfigs
  pub(super) async fn start_httpsig_rotation(&self, term_notify: Option<Arc<Notify>>) -> Result<()> {
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
      sleep(self.key_rotation_state.rotation_period).await;

      let Ok(httpsig_configs) = HttpSigPublicKeys::new(&self.key_rotation_state.key_types) else {
        error!("Failed to generate httpsig configs. Keep current config unchanged.");
        continue;
      };
      // generate new configs
      let mut lock = self.key_rotation_state.configs.write().await;
      let previous = lock.clone();
      *lock = httpsig_configs;
      drop(lock);
      // store previous configs to fill the gap between the new key and the old keys
      if self.count_previous_dh_public_keys > 0 {
        let mut lock = self.key_rotation_state.previous_configs.write().await;
        lock.push_back(previous);
        if lock.len() > self.count_previous_dh_public_keys {
          lock.pop_front();
        }
        drop(lock);
      }
      // update key map state with new self state
      self.key_map_state.update_with_new_self_state(&self.key_rotation_state).await;
    }
  }

  /// Start the periodic fetcher for httpsig public keys,
  pub(super) async fn start_httpsig_pk_fetcher_service(&self, term_notify: Option<Arc<Notify>>) -> Result<()> {
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
        let deserialized_configs = fetch_and_deserialize(&self.http_client, &config_endpoint_uri).await?;
        Ok(deserialized_configs) as Result<_>
      });
      let all_deserialized_configs = futures::future::join_all(futures).await;

      let config_with_info = all_deserialized_configs
        .iter()
        .zip(self.targets_info.iter())
        .collect::<Vec<_>>();
      config_with_info.iter().for_each(|(deserialized, info)| {
        if deserialized.is_err() {
          error!(
            "Failed to fetch httpsig public keys from {}: {}",
            info.configs_endpoint_uri,
            deserialized.as_ref().err().unwrap()
          );
        }
      });
      let config_with_info = config_with_info
        .iter()
        .filter(|(deserialized, _)| deserialized.is_ok())
        .map(|(deserialized, info)| (deserialized.as_ref().unwrap(), info.to_owned()))
        .collect::<Vec<_>>();

      // update key map state with new external configs fetched
      self
        .key_map_state
        .update_with_new_external_configs(&self.key_rotation_state, &config_with_info)
        .await;

      sleep(self.refetch_period).await;
    }
  }
}

/* ------------------------------------------------ */
/// Fetch and deserialize httpsig public keys from a given endpoint uri,
/// Vec<HttpSigConfigContents> object is retrieved for the endpoint
async fn fetch_and_deserialize<C>(http_client: &Arc<HttpClient<C>>, uri: &http::Uri) -> Result<Vec<HttpSigConfigContents>>
where
  C: Send + Sync + Connect + Clone + 'static,
{
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
    http_client.request(request.map(IncomingOr::Right)),
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
  let deserialized_configs = deserialized_configs
    .into_iter()
    .map(|config| config.contents)
    .collect::<Vec<_>>();
  info!("Fetched httpsig public keys from {}", uri);
  debug!("Fetched keys: {:#?}", deserialized_configs);
  Ok(deserialized_configs)
}
