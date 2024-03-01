use super::{
  keymap::{HttpSigKeyMapState, TypedKey},
  HttpSigKeyRotationState,
};
use crate::{
  constants::{
    HTTPSIG_COVERED_COMPONENTS, HTTPSIG_CUSTOM_SIGNATURE_NAME, HTTPSIG_KEY_REFETCH_TIMEOUT_SEC, HTTPSIG_REFETCH_USER_AGENT,
  },
  error::*,
  globals::{Globals, HttpSigDomainInfo},
  hyper_body::{full, BoxBody, IncomingOr},
  hyper_client::HttpClient,
  trace::*,
};
use base64::{engine::general_purpose, Engine as _};
use futures::{select, FutureExt};
use http::{header, Method, Request};
use http_body_util::{BodyExt, Empty};
use httpsig::prelude::*;
use httpsig_hyper::*;
use httpsig_proto::{DeriveSessionKey, Deserialize, HttpSigConfigContents, HttpSigConfigs, HttpSigPublicKeys, SessionKeyNonce};
use hyper::body::{Body, Bytes};
use hyper_util::client::legacy::connect::Connect;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Notify, time::sleep};
use tracing::instrument;

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
  key_rotation_state: Arc<HttpSigKeyRotationState>,

  /// Public key fetcher target domains
  targets_info: Vec<HttpSigDomainInfo>,

  // inner state and data structure updated by fetcher and used by router, target, relay
  key_map_state: Arc<HttpSigKeyMapState>,

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
    state: &Arc<HttpSigKeyRotationState>,
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
      key_rotation_state: state.clone(),
      refetch_period,
      targets_info,
      http_client: http_client.clone(),
      key_map_state: Arc::new(HttpSigKeyMapState::new()),
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

  #[instrument(name = "generate_request_with_signature", skip_all)]
  /// Append signature to request if available
  pub(crate) async fn generate_request_with_signature<T>(&self, request: Request<T>) -> Result<Request<IncomingOr<BoxBody>>>
  where
    T: Body + Sync + Send,
    <T as Body>::Data: Send,
  {
    // compute digest first
    let (parts, body) = request
      .set_content_digest(&ContentDigestType::Sha256)
      .await
      .map_err(|e| MODoHError::HttpSigComputeError(e.to_string()))?
      .into_parts();
    let body = IncomingOr::Right(full(body.into_bytes().await.unwrap()));
    let mut updated_request = Request::from_parts(parts, body);

    // signature params
    let covered_components = HTTPSIG_COVERED_COMPONENTS
      .iter()
      .map(|v| message_component::HttpMessageComponentId::try_from(*v))
      .collect::<std::result::Result<Vec<_>, _>>()
      .unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

    // find appropriate keys and add signature to the header
    let nexthop_host = updated_request.uri().host().unwrap_or_default();
    if let Some(hmac_key) = self.get_hmac_signing_key_by_domain(nexthop_host).await {
      debug!("sign request with hmac key: {nexthop_host}");
      let base64_url_nopad_nonce = general_purpose::URL_SAFE_NO_PAD.encode(hmac_key.nonce());
      let shared_key = SharedKey::HmacSha256(hmac_key.session_key().to_owned());
      signature_params.set_nonce(&base64_url_nopad_nonce);
      signature_params.set_alg(&AlgorithmName::HmacSha256);
      // key id must be the one of the shared master key via DHKex+HKDF
      signature_params.set_keyid(hmac_key.kem_kdf_derived_key_id());

      updated_request
        .set_message_signature(&signature_params, &shared_key, Some(HTTPSIG_CUSTOM_SIGNATURE_NAME))
        .await?;
      debug!("updated header with HMAC signature:\n{:#?}", updated_request.headers());
    } else {
      debug!("sign request with public key: {nexthop_host}");
      // TODO:
      warn!("not yet implemented for public key based signature. Skip signature for now.");
      // TODO:
    }

    Ok(updated_request)
  }

  #[instrument(name = "get_hmac_signing_key_by_domain", skip_all)]
  /// **SigningAPI**: Get a hmac key for the given domain for signing
  /// If found, derive the session key with random nonce.
  pub(crate) async fn get_hmac_signing_key_by_domain(&self, domain: &str) -> Option<SessionKeyNonce> {
    let available_key_ids = self.key_map_state.get_key_ids(domain).await;
    if available_key_ids.is_empty() {
      return None;
    }
    let key_id = available_key_ids.first().unwrap();
    let Some(typed_key) = self.key_map_state.get_typed_key(key_id).await else {
      return None;
    };
    let session_key_with_random_nonce = match typed_key {
      TypedKey::Dh(dh_key) => dh_key.derive_session_key_with_random_nonce(&mut rand::thread_rng()),
      _ => return None,
    };
    if session_key_with_random_nonce.is_err() {
      warn!("Failed to derive session key with random nonce for domain {}", domain);
      return None;
    }
    session_key_with_random_nonce.ok()
  }

  #[instrument(name = "get_pk_signing_key", skip_all)]
  /// **SigningAPI**: Get a secret key for signing (case if no hmac key is found)
  pub(crate) async fn get_pk_signing_key(&self) -> Option<SecretKey> {
    let available_secret_keys = self.key_map_state.get_pk_type_key_pairs().await;
    if available_secret_keys.is_empty() {
      return None;
    }
    available_secret_keys.first().map(|v| v.to_owned())
  }

  #[instrument(name = "get_hmac_verification_key_by_key_id", skip_all)]
  /// **VerificationAPI**: Search a hmac master key for the given key id
  /// If found, derive the session key for given nonce from the master key
  pub(crate) async fn get_hmac_verification_key_by_key_id(&self, key_id: &str, base64_nonce: &str) -> Option<SessionKeyNonce> {
    let typed_key = self.key_map_state.get_typed_key(key_id).await?;
    let master = match typed_key {
      TypedKey::Dh(dh_key) => dh_key.clone(),
      _ => return None,
    };

    let Ok(nonce) = general_purpose::URL_SAFE_NO_PAD.decode(base64_nonce) else {
      warn!("Failed to decode base64 nonce for key id {}", key_id);
      return None;
    };

    let Ok(session_key) = master.derive_session_key_with_nonce(nonce.as_slice()) else {
      warn!("Failed to derive session key with nonce for key id {}", key_id);
      return None;
    };

    Some(session_key)
  }

  #[instrument(name = "get_pk_verification_key_by_key_id", skip_all)]
  /// **VerificationAPI**: Get a public key for the given key id for verification (case if no hmac key is found)
  pub(crate) async fn get_pk_verification_key_by_key_id(&self, key_id: &str) -> Option<PublicKey> {
    let typed_key = self.key_map_state.get_typed_key(key_id).await?;
    let public_key = match typed_key {
      TypedKey::Pk(pk) => pk,
      _ => return None,
    };
    Some(public_key)
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
      sleep(self.key_rotation_state.rotation_period).await;

      let Ok(httpsig_configs) = HttpSigPublicKeys::new(&self.key_rotation_state.key_types) else {
        error!("Failed to generate httpsig configs. Keep current config unchanged.");
        continue;
      };
      let mut lock = self.key_rotation_state.configs.write().await;
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
      self.key_map_state.update(&self.key_rotation_state, &config_with_info).await;

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
  let deserialized_configs = deserialized_configs.into_iter().map(|config| config.contents).collect();
  info!("Fetched httpsig public keys from {}", uri);
  debug!("Fetched keys: {:#?}", deserialized_configs);
  Ok(deserialized_configs)
}
