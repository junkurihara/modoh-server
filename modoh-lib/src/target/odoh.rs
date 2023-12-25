// Porting of https://github.com/DNSCrypt/doh-server/blob/master/src/libdoh/src/odoh.rs

use crate::error::*;
use hyper::body::Bytes;
use odoh_rs::{
  Deserialize, ObliviousDoHConfig, ObliviousDoHConfigs, ObliviousDoHKeyPair, ObliviousDoHMessage,
  ObliviousDoHMessagePlaintext, OdohSecret, ResponseNonce, Serialize,
};
use rand::Rng;
use tracing::instrument;

#[derive(Clone)]
/// ODoH public key
pub struct ODoHPublicKey {
  key_pair: ObliviousDoHKeyPair,
  serialized_configs: Vec<u8>,
}

impl ODoHPublicKey {
  /// Create a new ODoH public key
  pub fn new() -> Result<ODoHPublicKey> {
    let key_pair = ObliviousDoHKeyPair::new(&mut rand::thread_rng());
    let config = ObliviousDoHConfig::from(key_pair.public().clone());
    let mut serialized_configs = Vec::new();
    ObliviousDoHConfigs::from(vec![config])
      .serialize(&mut serialized_configs)
      .map_err(MODoHError::ODoHConfigError)?;
    Ok(ODoHPublicKey {
      key_pair,
      serialized_configs,
    })
  }

  /// Get serialized configs
  pub fn as_config(&self) -> &[u8] {
    &self.serialized_configs
  }

  #[instrument(level = "debug", skip_all)]
  /// Decrypt ODoH query
  pub fn decrypt_query(&self, encrypted_query: Vec<u8>) -> HttpResult<(Vec<u8>, ODoHQueryContext)> {
    let odoh_query =
      ObliviousDoHMessage::deserialize(&mut Bytes::from(encrypted_query)).map_err(|_| HttpError::InvalidODoHQuery)?;

    match self.key_pair.public().identifier() {
      Ok(key_id) => {
        if !key_id.eq(&odoh_query.key_id()) {
          return Err(HttpError::ODoHStaleKey);
        }
      }
      Err(_) => return Err(HttpError::InvalidODoHQuery),
    };
    let (query, server_secret) = match odoh_rs::decrypt_query(&odoh_query, &self.key_pair) {
      Ok((pq, ss)) => (pq, ss),
      Err(_) => return Err(HttpError::InvalidODoHQuery),
    };
    let context = ODoHQueryContext {
      query: query.clone(),
      server_secret,
    };
    Ok((query.into_msg().to_vec(), context))
  }
}

#[derive(Clone, Debug)]
/// ODoH query context
pub struct ODoHQueryContext {
  /// ODoH query
  query: ObliviousDoHMessagePlaintext,
  /// ODoH server secret
  server_secret: OdohSecret,
}

impl ODoHQueryContext {
  #[instrument(level = "debug", skip_all)]
  /// Encrypt raw DNS response
  pub fn encrypt_response(self, response_body: Vec<u8>) -> HttpResult<Vec<u8>> {
    let response_nonce = rand::thread_rng().gen::<ResponseNonce>();
    let response_body_ = ObliviousDoHMessagePlaintext::new(response_body, 0);
    let encrypted_response =
      odoh_rs::encrypt_response(&self.query, &response_body_, self.server_secret, response_nonce)
        .map_err(|_| HttpError::InvalidODoHResponse)?;
    let mut encrypted_response_bytes = Vec::new();
    encrypted_response
      .serialize(&mut encrypted_response_bytes)
      .map_err(|_| HttpError::InvalidODoHResponse)?;
    Ok(encrypted_response_bytes)
  }
}
