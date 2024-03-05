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

  /// Force httpsig verification for all requests regardless of the source ip validation result.
  pub(crate) force_verification: bool,

  /// Ignore httpsig verification result and continue to serve the request.
  pub(crate) ignore_verification_result: bool,
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
    let force_verification = httpsig_config.force_verification;
    let ignore_verification_result = httpsig_config.ignore_verification_result;

    let handler = Arc::new(Self {
      key_rotation_state: state.clone(),
      refetch_period,
      targets_info,
      http_client: http_client.clone(),
      key_map_state: Arc::new(HttpSigKeyMapState::new()),
      force_verification,
      ignore_verification_result,
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

  #[instrument(name = "generate_request_with_digest", skip_all)]
  /// Compute content digest for the request body
  async fn generate_request_with_digest<T>(&self, request: Request<T>) -> Result<Request<IncomingOr<BoxBody>>>
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
    let updated_request = Request::from_parts(parts, body);
    Ok(updated_request)
  }

  #[instrument(name = "verify_request_with_signature", skip_all)]
  /// Verify signature of the request if available
  pub(crate) async fn verify_signed_request<T>(&self, request: &Request<T>) -> Result<()>
  where
    T: Body + Sync + Send,
    <T as Body>::Data: Send,
  {
    // get key ids with nonce
    let contained_key_ids_with_nonce = request
      .get_signature_params()?
      .iter()
      .filter_map(|params| params.keyid.as_ref().map(|k| (k.to_owned(), params.nonce.clone())))
      .collect::<Vec<_>>();
    // find available keys
    let available_keys_future = contained_key_ids_with_nonce.iter().map(|(key_id, nonce)| async {
      self
        .key_map_state
        .get_typed_key(key_id)
        .await
        .map(|typed_key| (key_id.to_owned(), nonce.clone(), typed_key))
    });
    let available_keys = futures::future::join_all(available_keys_future)
      .await
      .into_iter()
      .flatten()
      .collect::<Vec<_>>();

    // TODO: validate covered-component!
    /* ---------- */
    // verify signatures with available keys
    // first try dhkex+hkdf derived hmac key
    let dh_available_keys = available_keys
      .iter()
      .filter_map(|(key_id, nonce, typed_key)| match typed_key {
        TypedKey::Dh(dh_key) => match nonce {
          Some(nonce) => {
            let nonce_bytes = general_purpose::STANDARD.decode(nonce).ok()?;
            let session_key = dh_key.derive_session_key_with_nonce(nonce_bytes.as_slice()).ok()?;
            let shared_key = SharedKey::HmacSha256(session_key.session_key().to_owned());
            Some((key_id, shared_key))
          }
          _ => None,
        },
        _ => None,
      })
      .collect::<Vec<_>>();
    if !dh_available_keys.is_empty() {
      let dh_verify_res_future = dh_available_keys
        .iter()
        .map(|(key_id, shared_key)| request.verify_message_signature(shared_key, Some(key_id)));
      let dh_verify_res = futures::future::join_all(dh_verify_res_future)
        .await
        .iter()
        .any(|v| v.is_ok());
      // if dh_verify_res is true, then the signature itself is ok.
      if dh_verify_res {
        return Ok(());
      }
      // Even if dh available key is found, if the signature is invalid, then it is invalid. skip the pk verification.
      return Err(MODoHError::HttpSigVerificationError(
        "Failed to verify signature with DH key".to_string(),
      ));
    }
    /* ---------- */
    // if no dh key is found, try public key based signature
    let pk_available_keys = available_keys
      .iter()
      .filter_map(|(key_id, _, typed_key)| match typed_key {
        TypedKey::Pk(pk_key) => Some((key_id, pk_key)),
        _ => None,
      })
      .collect::<Vec<_>>();
    if pk_available_keys.is_empty() {
      return Err(MODoHError::HttpSigVerificationError(
        "No public key found for verification".to_string(),
      ));
    }
    let pk_verify_res_future = pk_available_keys
      .iter()
      .map(|(key_id, pk_key)| request.verify_message_signature(*pk_key, Some(key_id)));
    let pk_verify_res = futures::future::join_all(pk_verify_res_future)
      .await
      .iter()
      .any(|v| v.is_ok());
    if pk_verify_res {
      return Ok(());
    }
    return Err(MODoHError::HttpSigVerificationError(
      "Failed to verify signature with public key".to_string(),
    ));
  }

  /// Verify content digest of the request body
  pub(crate) async fn verify_content_digest<T>(&self, request: Request<T>) -> Result<Request<IncomingOr<BoxBody>>>
  where
    T: Body + Sync + Send,
    <T as Body>::Data: Send,
  {
    let (parts, body) = request
      .verify_content_digest()
      .await
      .map_err(|e| MODoHError::HttpSigVerificationError(format!("Failed to verify content-digest header: {e}")))?
      .into_parts();

    let body = IncomingOr::Right(full(body.into_bytes().await.unwrap()));
    let updated_request = Request::from_parts(parts, body);

    Ok(updated_request)
  }

  #[instrument(name = "generate_request_with_signature", skip_all)]
  /// Append signature to request if available
  pub(crate) async fn generate_signed_request<T>(&self, request: Request<T>) -> Result<Request<IncomingOr<BoxBody>>>
  where
    T: Body + Sync + Send,
    <T as Body>::Data: Send,
  {
    // compute digest first
    let mut updated_request = self.generate_request_with_digest(request).await?;

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
      // First checks DHKex+HKDF derived hmac key
      debug!(nexthop_host, "Request will be signed with hmac key");
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
    } else if let Some(pk_signing_key) = self.get_pk_signing_key().await {
      // If no hmac key is found, try use public key based signature
      debug!(nexthop_host, "Request will be signed with public key");
      signature_params.set_key_info(&pk_signing_key);
      signature_params.set_random_nonce();

      updated_request
        .set_message_signature(&signature_params, &pk_signing_key, Some(HTTPSIG_CUSTOM_SIGNATURE_NAME))
        .await?;
      debug!(
        "updated header with public-key based signature:\n{:#?}",
        updated_request.headers()
      );
    } else {
      debug!(nexthop_host, "No key found for signing the request");
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
