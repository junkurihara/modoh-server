use super::{
  keymap::{HttpSigKeyMapState, TypedKey},
  HttpSigKeyRotationState,
};
use crate::{
  constants::{
    HTTPSIG_COVERED_COMPONENTS, HTTPSIG_CUSTOM_SIGNATURE_NAME, HTTPSIG_CUSTOM_SIGNED_WITH_LATEST_KEY,
    HTTPSIG_CUSTOM_SIGNED_WITH_STALE_KEY, HTTPSIG_EXP_DURATION_SEC,
  },
  error::*,
  globals::Globals,
  hyper_body::{full, BoxBody, IncomingOr},
  hyper_client::HttpClient,
  trace::*,
};
use base64::{engine::general_purpose, Engine as _};
use http::Request;
use httpsig::prelude::*;
use httpsig_hyper::*;
use httpsig_proto::{DeriveSessionKey, SessionKeyNonce};
use httpsig_registry::HttpSigDomainInfo;
use hyper::body::Body;
use hyper_util::client::legacy::connect::Connect;
use indexmap::IndexMap;
use std::{sync::Arc, time::Duration};
use tracing::{instrument, Instrument};

/// Generation is the generation of key pair(s) generated by the self-key rotation.
/// Key pairs of generation 0 are the latest key pairs, and those of generation 1, 2, ... are the previous key pairs.
/// We don't basically use ones of generation i > 0 for both signing and verification.
/// However, we keep them for a while to fill the gap of the key rotation period by adding and verifying signature for previous key.
type Generation = usize;
type KeyId = String;

type SignatureName = String;
type IsSenderStaleKey = bool;
type VerificationResult = IndexMap<KeyId, (std::result::Result<SignatureName, HyperSigError>, IsSenderStaleKey)>;

#[derive(Clone)]
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
  /// force to refetch notifier for the public keys
  pub(super) force_refetch_notify: Arc<tokio::sync::Notify>,

  /// hyper client
  pub(super) http_client: Arc<HttpClient<C, B>>,

  /// Service state for exposed httpsig public keys
  pub(super) key_rotation_state: Arc<HttpSigKeyRotationState>,

  /// Public key fetcher target domains
  pub(super) targets_info: Vec<HttpSigDomainInfo>,

  // inner state and data structure updated by fetcher and used by router, target, relay
  pub(super) key_map_state: Arc<HttpSigKeyMapState>,

  /// Public key refetch period
  pub(super) refetch_period: Duration,

  /// Generations of accepted previous DH public keys to fill the gap of the key rotation period.
  pub(super) previous_dh_public_keys_gen: usize,

  /// Generations of past keys generating signatures simultaneously with the current key
  pub(super) generation_transition_margin: usize,

  /// Force httpsig verification for all requests regardless of the source ip validation result.
  pub(crate) force_verification: bool,

  /// Ignore httpsig verification result and continue to serve the request.
  pub(crate) ignore_verification_result: bool,

  /// Ignore httpsig verification result and continue to serve the request, only if the source ip is allowed.
  pub(crate) ignore_verification_result_for_allowed_source_ips: bool,

  /// covered components for the signature
  covered_components: Vec<message_component::HttpMessageComponentId>,
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

    // TODO: registryとベタ書きのdomainの情報を統合するロジックの実装
    // TODO: 一発目はtry_newの中で。それ以降、periodic updateをかけるようにする。
    // TODO: target domain filteringについても整合性を取れるようにしておかないとやばい
    let targets_info = httpsig_config
      .enabled_domains
      .iter()
      .map(|v| HttpSigDomainInfo::new(v.configs_endpoint_domain.as_str(), v.dh_signing_target_domain.clone()))
      .collect::<Vec<_>>();

    let refetch_period = httpsig_config.refetch_period;
    let previous_dh_public_keys_gen = httpsig_config.previous_dh_public_keys_gen;
    let generation_transition_margin = httpsig_config.generation_transition_margin;
    let force_verification = httpsig_config.force_verification;
    let ignore_verification_result = httpsig_config.ignore_verification_result;
    let ignore_verification_result_for_allowed_source_ips = httpsig_config.ignore_verification_result_for_allowed_source_ips;
    // signature params
    let covered_components = HTTPSIG_COVERED_COMPONENTS
      .iter()
      .map(|v| message_component::HttpMessageComponentId::try_from(*v))
      .collect::<std::result::Result<Vec<_>, _>>()
      .unwrap();

    let force_refetch_notify = Arc::new(tokio::sync::Notify::new());

    let handler = Arc::new(Self {
      force_refetch_notify,
      key_rotation_state: state.clone(),
      refetch_period,
      targets_info,
      http_client: http_client.clone(),
      key_map_state: Arc::new(HttpSigKeyMapState::new()),
      previous_dh_public_keys_gen,
      generation_transition_margin,
      force_verification,
      ignore_verification_result,
      ignore_verification_result_for_allowed_source_ips,
      covered_components,
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

  #[instrument(name = "verify_signed_request", skip_all)]
  /// Verify signature of the request if available
  pub(crate) async fn verify_signed_request<T>(&self, request: &Request<T>) -> Result<()>
  where
    T: Body + Sync + Send,
    <T as Body>::Data: Send,
  {
    // get (key id, nonce) tuples for non-expired signatures
    let available_keys_map = self.find_available_keys_for_request(request).await?;
    // TODO: validate covered-component!

    /* ---------- */
    // verify signatures with available keys
    // first try dhkex+hkdf derived hmac key
    if let Some(dh_verify_res) = self.verify_httpsig_with_dh_keys(request, &available_keys_map).await {
      // if some of dh_verify_res is true, then the signature itself is ok.
      let ok_res = dh_verify_res
        .iter()
        .filter(|(_, (v, _))| v.is_ok())
        .collect::<IndexMap<_, _>>();
      if !ok_res.is_empty() {
        // If the signature is signed with a stale key, then we need to fetch the latest key when the signature is valid.
        // If it is invalid, it may be compromised one. In this case, we don't need to fetch the latest key.
        if ok_res.iter().any(|(_, (_, is_sender_stale))| *is_sender_stale) {
          // fetch the latest key
          warn!("Having sender's stale key. Fetch the latest key");
          self.force_refetch_notify.notify_waiters();
        }

        return Ok(());
      }
      // Even if dh available key is found, if the signature is invalid, then it is invalid. skip the pk verification.
      return Err(MODoHError::HttpSigVerificationError(
        "Failed to verify signature with DH key".to_string(),
      ));
    }

    /* ---------- */
    // if no dh key is found, try public key based signature
    let pk_available_keys = available_keys_map
      .iter()
      .filter_map(|(key_id, (_, typed_key))| match typed_key {
        TypedKey::Pk(pk_key) => Some((key_id, pk_key)),
        _ => None,
      })
      .collect::<Vec<_>>();
    if pk_available_keys.is_empty() {
      return Err(MODoHError::HttpSigVerificationError(
        "No public key found for verification".to_string(),
      ));
    }
    debug!(
      "No available DHKex+HKDF key. Found {} keys for public key based signature",
      pk_available_keys.len()
    );
    let pk_verify_res_future = pk_available_keys
      .iter()
      .map(|(key_id, pk_key)| request.verify_message_signature(&pk_key.inner, Some(key_id)));
    let pk_verify_res = futures::future::join_all(pk_verify_res_future)
      .instrument(tracing::info_span!("pk_verify_res"))
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

  #[instrument(name = "verify_httpsig_with_dh_keys", skip_all)]
  /// Verify with hmac key
  async fn verify_httpsig_with_dh_keys<T>(
    &self,
    request_with_digest: &Request<T>,
    available_keys_map: &IndexMap<KeyId, (HttpSignatureParams, TypedKey)>,
  ) -> Option<VerificationResult>
  where
    T: Body + Sync + Send,
    <T as Body>::Data: Send,
  {
    let dh_available_keys = available_keys_map
      .iter()
      .filter_map(|(key_id, (params, typed_key))| match typed_key {
        TypedKey::Dh(dh_key) => match &params.nonce {
          Some(nonce) => {
            let nonce_bytes = general_purpose::STANDARD.decode(nonce).ok()?;
            let session_key = dh_key.inner.derive_session_key_with_nonce(nonce_bytes.as_slice()).ok()?;
            let shared_key = SharedKey::HmacSha256(session_key.session_key().to_owned());
            let is_sender_stale = params
              .tag
              .as_ref()
              .map(|v| v.starts_with(HTTPSIG_CUSTOM_SIGNED_WITH_STALE_KEY))
              .unwrap_or(false);
            Some((key_id, (shared_key, is_sender_stale)))
          }
          _ => None,
        },
        _ => None,
      })
      .collect::<IndexMap<_, _>>();
    if dh_available_keys.is_empty() {
      return None;
    }
    debug!("Found {} keys for DHKex+HKDF derived hmac key", dh_available_keys.len());
    let dh_verify_res_future = dh_available_keys
      .into_iter()
      .map(|(key_id, (shared_key, is_sender_stale))| async move {
        let res = request_with_digest.verify_message_signature(&shared_key, Some(key_id)).await;
        (key_id, (res, is_sender_stale))
      });
    let dh_verify_res = futures::future::join_all(dh_verify_res_future)
      .instrument(tracing::info_span!("dh_verify_res"))
      .await
      .into_iter()
      .map(|(k, v)| (k.to_owned(), v))
      .collect::<IndexMap<_, _>>();

    Some(dh_verify_res)
  }

  #[instrument(name = "find_available_keys_for_request", skip_all)]
  /// Find available keys from the key map to verify the given request
  async fn find_available_keys_for_request<T>(
    &self,
    request: &Request<T>,
  ) -> Result<IndexMap<KeyId, (HttpSignatureParams, TypedKey)>>
  where
    T: Body + Sync + Send,
    <T as Body>::Data: Send,
  {
    // get (key id, nonce) tuples for non-expired signatures
    let contained_key_ids_params_map = request
      .get_signature_params()?
      .iter()
      .filter_map(|(_name, params)| {
        if params.is_expired() || params.tag.is_none() {
          warn!("Expired or no-tag signature found");
          return None;
        }
        params.keyid.as_ref().map(|k| (k.to_owned(), params.clone()))
      })
      .collect::<IndexMap<_, _>>();
    debug!(
      "(key_id, nonce) tuple(s) contained in a request: {:?}",
      contained_key_ids_params_map
    );
    // find available keys
    let available_keys_future = contained_key_ids_params_map.into_iter().map(|(key_id, params)| async {
      self
        .key_map_state
        .get_typed_key(&key_id)
        .await
        .map(|typed_key| (key_id, (params, typed_key)))
    });
    let available_keys_map = futures::future::join_all(available_keys_future)
      .await
      .into_iter()
      .flatten()
      .collect::<IndexMap<_, _>>();
    debug!("available keys: {} keys found", available_keys_map.len());
    Ok(available_keys_map)
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
      .instrument(tracing::info_span!("set_content_digest"))
      .await
      .map_err(|e| MODoHError::HttpSigComputeError(e.to_string()))?
      .into_parts();
    let body = IncomingOr::Right(full(body.into_bytes().await.unwrap()));
    let updated_request = Request::from_parts(parts, body);
    Ok(updated_request)
  }

  #[instrument(name = "verify_and_update_content_digest", skip_all)]
  /// Verify content digest of the request body
  pub(crate) async fn verify_content_digest<T>(&self, request: Request<T>) -> Result<Request<IncomingOr<BoxBody>>>
  where
    T: Body + Sync + Send,
    <T as Body>::Data: Send,
  {
    let (parts, body) = request
      .verify_content_digest()
      .instrument(tracing::info_span!("verify_content_digest"))
      .await
      .map_err(|e| MODoHError::HttpSigVerificationError(format!("Failed to verify content-digest header: {e}")))?
      .into_parts();

    let body = IncomingOr::Right(full(body.into_bytes().await.unwrap()));
    let updated_request = Request::from_parts(parts, body);

    Ok(updated_request)
  }

  #[instrument(name = "generate_signed_request", skip_all)]
  /// Append signature to request if available
  /// For DHKex+HKDF signature, we add multiple signatures considering the generation transition margin.
  /// On the other hand, for now, we do not care about the generation transition margin for PK-based type of signature.
  pub(crate) async fn generate_signed_request<T>(&self, request: Request<T>) -> Result<Request<IncomingOr<BoxBody>>>
  where
    T: Body + Sync + Send,
    <T as Body>::Data: Send,
  {
    // compute digest first
    let mut updated_request = self.generate_request_with_digest(request).await?;

    // try to sign with hmac key(s) considering the generation transition margin
    match self.add_httpsig_with_dh_keys(&mut updated_request).await {
      Ok(()) => return Ok(updated_request),
      Err(MODoHError::NoDHKeyFound) => {}
      Err(e) => {
        return Err(e);
      }
    };

    // try to sign with asymmetric key.
    if let Some(pk_signing_key) = self.get_pk_signing_key().await {
      // If no hmac key is found, try use public key based signature
      // debug!(nexthop_host, "Request will be signed with public key");
      let mut signature_params = HttpSignatureParams::try_new(&self.covered_components).unwrap();
      signature_params.set_key_info(&pk_signing_key);
      signature_params.set_random_nonce();
      signature_params.set_expires_with_duration(Some(HTTPSIG_EXP_DURATION_SEC));
      signature_params.set_tag(HTTPSIG_CUSTOM_SIGNED_WITH_LATEST_KEY);

      updated_request
        .set_message_signature(&signature_params, &pk_signing_key, Some(HTTPSIG_CUSTOM_SIGNATURE_NAME))
        .instrument(tracing::info_span!("set_message_signature_pk"))
        .await?;
      debug!(
        "updated header with public-key based signature:\n{:#?}",
        updated_request.headers()
      );
    } else {
      debug!("No key found for signing the request");
    }

    Ok(updated_request)
  }

  #[instrument(name = "add_httpsig_with_dh_keys", skip_all)]
  /// Sign with hmac key
  async fn add_httpsig_with_dh_keys<T>(&self, request_with_digest: &mut Request<T>) -> Result<()>
  where
    T: Body + Sync + Send,
    <T as Body>::Data: Send,
  {
    // find appropriate keys and add signature to the header
    let target_host = request_with_digest.uri().host().unwrap_or_default();
    let Some(hmac_keys_with_gen) = self.get_hmac_signing_key_by_domain(target_host).await else {
      return Err(MODoHError::NoDHKeyFound);
    };
    // First checks DHKex+HKDF derived hmac key
    debug!(
      target_host,
      "Request will be signed with hmac keys of {} generation(s)",
      hmac_keys_with_gen.len()
    );
    let params_key_name_for_gen = hmac_keys_with_gen
      .iter()
      .map(|(gen, hmac_key)| {
        let mut signature_params = HttpSignatureParams::try_new(&self.covered_components).unwrap();
        let base64_nonce = general_purpose::STANDARD.encode(hmac_key.nonce());
        let shared_key = SharedKey::HmacSha256(hmac_key.session_key().to_owned());
        signature_params.set_nonce(&base64_nonce);
        signature_params.set_alg(&AlgorithmName::HmacSha256);
        signature_params.set_expires_with_duration(Some(HTTPSIG_EXP_DURATION_SEC));
        // key id must be the one of the shared master key via DHKex+HKDF
        signature_params.set_keyid(hmac_key.kem_kdf_derived_key_id());
        let sig_name = if *gen == 0 {
          signature_params.set_tag(HTTPSIG_CUSTOM_SIGNED_WITH_LATEST_KEY);
          HTTPSIG_CUSTOM_SIGNATURE_NAME.to_string()
        } else {
          signature_params.set_tag(HTTPSIG_CUSTOM_SIGNED_WITH_STALE_KEY);
          format!("{HTTPSIG_CUSTOM_SIGNATURE_NAME}-{gen}")
        };
        (signature_params, shared_key, Some(sig_name))
      })
      .collect::<Vec<_>>();
    let signing_inputs = params_key_name_for_gen
      .iter()
      .map(|(p, k, n)| (p, k, n.as_ref().map(|v| v.as_str())))
      .collect::<Vec<_>>();
    request_with_digest
      .set_message_signatures(signing_inputs.as_slice())
      .instrument(tracing::info_span!("set_message_signature_dh"))
      .await?;

    debug!("updated header with HMAC signature(s)\n {:#?}", request_with_digest.headers());
    Ok(())
  }

  #[instrument(name = "get_hmac_signing_key_by_domain", skip_all)]
  /// **SigningAPI**: Get hmac keys for the given domain for latest and transitional generations
  /// If found, derive the session key with random nonce.
  pub(crate) async fn get_hmac_signing_key_by_domain(&self, domain: &str) -> Option<IndexMap<Generation, SessionKeyNonce>> {
    let available_key_ids = self
      .key_map_state
      .get_key_ids(domain)
      .await
      .into_iter()
      .filter(|(generation, key_ids)| *generation <= self.generation_transition_margin && !key_ids.is_empty())
      .collect::<IndexMap<_, _>>();
    if available_key_ids.is_empty() {
      return None;
    }
    let one_key_id_for_each_generation = available_key_ids.iter().map(|(gen, key_ids)| (gen, key_ids.first().unwrap()));
    let futs = one_key_id_for_each_generation.map(|(gen, key_id)| async move {
      let typed_key = self.key_map_state.get_typed_key(key_id).await?;
      let session_key_with_random_nonce = match typed_key {
        TypedKey::Dh(dh_key) => dh_key.inner.derive_session_key_with_random_nonce(&mut rand::thread_rng()),
        _ => return None,
      };
      if session_key_with_random_nonce.is_err() {
        warn!("Failed to derive session key with random nonce for {domain} {key_id}");
        return None;
      }
      session_key_with_random_nonce.ok().map(|v| (*gen, v))
    });
    let session_keys_with_random_nonce = futures::future::join_all(futs)
      .await
      .into_iter()
      .flatten()
      .collect::<IndexMap<_, _>>();

    // assertions
    if session_keys_with_random_nonce.is_empty() {
      return None;
    }
    if session_keys_with_random_nonce.get(&0).is_none() {
      warn!("No latest available key for signing for domain {domain}");
      return None;
    }
    if !session_keys_with_random_nonce
      .iter()
      .enumerate()
      .all(|(i, (gen, _))| i == *gen)
    {
      warn!("Key map state might be broken!");
      return None;
    }
    Some(session_keys_with_random_nonce)
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

    let Ok(nonce) = general_purpose::STANDARD.decode(base64_nonce) else {
      warn!("Failed to decode base64 nonce for key id {}", key_id);
      return None;
    };

    let Ok(session_key) = master.inner.derive_session_key_with_nonce(nonce.as_slice()) else {
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
      TypedKey::Pk(pk) => pk.inner,
      _ => return None,
    };
    Some(public_key)
  }
}
