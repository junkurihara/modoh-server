use super::{error::HttpSigResult, DhKemTypes};
use bytes::Bytes;
use hpke::Kem;
use odoh_rs::{ObliviousDoHConfig, ObliviousDoHConfigs};
use rand::{CryptoRng, RngCore};

/// Current HTTP signature configuration served at the endpoint
/// This is actually imported from odoh_rs::ObliviousDoHConfigs
pub(crate) type HttpSigConfigs = ObliviousDoHConfigs;

/// Individual HTTP signature configuration
pub(crate) type HttpSigConfig = ObliviousDoHConfig;

/// Individual HTTP signature configuration contents
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSigConfigContents {
  kem_id: u16,
  // kdf_id: u16,
  // aead_id: u16,
  // public_key: Bytes,
}

#[derive(Clone)]
/// HttpSig key pair
pub(crate) struct HttpSigKeyPair<T: Kem> {
  private_key: <T as Kem>::PrivateKey,
  public_key: HttpSigConfigContents,
}

#[derive(Clone)]
/// HttpSig public key
pub struct HttpSigPublicKey {
  key_pairs: Vec<()>,
  serialized_configs: Vec<u8>,
}

impl HttpSigPublicKey {
  /// Create a new ODoH public key
  pub fn new(dh_kem_types: &[DhKemTypes]) -> HttpSigResult<Self> {
    // let hpke_kem_type = dh_kem_types.iter().map(|t| {
    //   let kem: Box<dyn Kem> = match t {
    //     DhKemTypes::X25519HkdfSha256 => Box::new(hpke::kem::X25519HkdfSha256),
    //     DhKemTypes::P256HkdfSha256 => Box::new(hpke::kem::DhP256HkdfSha256),
    //   };
    // });
    // let key_pair = ObliviousDoHKeyPair::new(&mut rand::thread_rng());
    // let config = ObliviousDoHConfig::from(key_pair.public().clone());
    // let mut serialized_configs = Vec::new();
    // ObliviousDoHConfigs::from(vec![config])
    //   .serialize(&mut serialized_configs)
    //   .map_err(MODoHError::ODoHConfigError)?;
    // Ok(ODoHPublicKey {
    //   key_pair,
    //   serialized_configs,
    // })
    todo!()
  }
}

fn generate_key_pair<K: Kem, R: RngCore + CryptoRng>(target_kem: K, mut rng: &mut R) -> HttpSigKeyPair<K> {
  let (private_key, public_key) = <K as Kem>::gen_keypair(&mut rng);

  let contents = HttpSigConfigContents {
    kem_id: <K as Kem>::KEM_ID,
    // kdf_id: <K as Kem>,
    //   aead_id: target_kem.aead_id(),
    //   public_key: public_key.to_bytes().to_vec().into(),
  };

  HttpSigKeyPair {
    private_key,
    public_key: contents,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use hpke::kem::X25519HkdfSha256;
  use rand::thread_rng;

  #[test]
  fn test_generate_key_pair() {
    let mut rng = thread_rng();
    generate_key_pair(X25519HkdfSha256, &mut rng);
  }
}
