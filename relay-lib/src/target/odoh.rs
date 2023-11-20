// Porting of https://github.com/DNSCrypt/doh-server/blob/master/src/libdoh/src/odoh.rs

use crate::error::*;
use odoh_rs::{
  Deserialize, ObliviousDoHConfig, ObliviousDoHConfigs, ObliviousDoHKeyPair, ObliviousDoHMessage,
  ObliviousDoHMessagePlaintext, OdohSecret, ResponseNonce, Serialize,
};

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

  pub fn as_config(&self) -> &[u8] {
    &self.serialized_configs
  }

  // pub fn decrypt_query(self, encrypted_query: Vec<u8>) -> Result<(Vec<u8>, ODoHQueryContext), DoHError> {
  //   let odoh_query =
  //     ObliviousDoHMessage::deserialize(&mut bytes::Bytes::from(encrypted_query)).map_err(|_| DoHError::InvalidData)?;
  //   match self.key_pair.public().identifier() {
  //     Ok(key_id) => {
  //       if !key_id.eq(&odoh_query.key_id()) {
  //         return Err(DoHError::StaleKey);
  //       }
  //     }
  //     Err(_) => return Err(DoHError::InvalidData),
  //   };
  //   let (query, server_secret) = match odoh_rs::decrypt_query(&odoh_query, &self.key_pair) {
  //     Ok((pq, ss)) => (pq, ss),
  //     Err(_) => return Err(DoHError::InvalidData),
  //   };
  //   let context = ODoHQueryContext {
  //     query: query.clone(),
  //     server_secret,
  //   };
  //   Ok((query.into_msg().to_vec(), context))
  // }
}

#[derive(Clone, Debug)]
/// ODoH query context
pub struct ODoHQueryContext {
  query: ObliviousDoHMessagePlaintext,
  server_secret: OdohSecret,
}
