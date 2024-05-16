use crate::{
  common::{read_lengthed, to_u16, Deserialize, Serialize},
  error::HttpSigError,
};
use bytes::{Buf, BufMut, Bytes};
use hpke::{
  kem::{DhP256HkdfSha256, X25519HkdfSha256},
  Kem, Serializable,
};
use httpsig::prelude::{AlgorithmName, PublicKey, SecretKey};
use rand::{CryptoRng, RngCore};

/* ------------------------------------------- */
#[derive(Clone, Default, Debug, PartialEq, Eq)]
/// Public key types used for httpsig's public-key-based signature.
pub enum HttpSigPkTypes {
  #[default]
  /// ed25519
  Ed25519,
  /// es256/ecdsa-p256-sha256
  EcdsaP256Sha256,
}

impl HttpSigPkTypes {
  /// Get the Public key signature algorithm ID, which is the same as the KEM ID in hpke
  pub(crate) fn alg_id(&self) -> u16 {
    match self {
      HttpSigPkTypes::Ed25519 => X25519HkdfSha256::KEM_ID,
      HttpSigPkTypes::EcdsaP256Sha256 => DhP256HkdfSha256::KEM_ID,
    }
  }

  /// Generate new key pair
  pub(crate) fn generate_key_pair<R>(&self, mut rng: &mut R) -> HttpSigPkKeyPair
  where
    R: RngCore + CryptoRng,
  {
    let (sk_bytes, pk_bytes) = match self {
      HttpSigPkTypes::Ed25519 => {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::from_slice(&buf).unwrap());
        (kp.sk.seed().to_vec(), kp.pk.as_slice().to_vec())
      }
      HttpSigPkTypes::EcdsaP256Sha256 => {
        let (sk, pk) = DhP256HkdfSha256::gen_keypair(&mut rng);
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
      }
    };

    let contents = HttpSigPkConfigContents {
      alg_id: self.alg_id(),
      public_key: pk_bytes.into(),
    };

    HttpSigPkKeyPair {
      private_key: sk_bytes.into(),
      public_key: contents,
    }
  }
}

/* ------------------------------------------- */
#[derive(Clone, Debug, PartialEq, Eq)]
/// Key pair for HttpSig public key signature verification
pub struct HttpSigPkKeyPair {
  pub(crate) private_key: Bytes,
  pub(crate) public_key: HttpSigPkConfigContents,
}

impl HttpSigPkKeyPair {
  /// export public key as `httpsig` crate's `PublicKey`
  pub fn try_export_pk(&self) -> Result<PublicKey, HttpSigError> {
    self.public_key.try_export()
  }
  /// export private key as `httpsig` crate's `SecretKey`
  pub fn try_export_sk(&self) -> Result<SecretKey, HttpSigError> {
    let alg_name = self.public_key.alg_name();
    let res = SecretKey::from_bytes(alg_name, self.private_key.to_vec().as_slice())?;
    Ok(res)
  }
}

/* ------------------------------------------- */
/// Configuration contents for HttpSig public key signature verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSigPkConfigContents {
  pub(crate) alg_id: u16,
  pub(crate) public_key: Bytes,
}
impl HttpSigPkConfigContents {
  /// export public key as `httpsig` crate's `PublicKey`
  pub fn try_export(&self) -> Result<PublicKey, HttpSigError> {
    let alg_name = self.alg_name();
    let res = PublicKey::from_bytes(alg_name, self.public_key.to_vec().as_slice())?;
    Ok(res)
  }
  /// Get the algorithm name in `httpsig` crate
  pub(crate) fn alg_name(&self) -> AlgorithmName {
    match self.alg_id {
      X25519HkdfSha256::KEM_ID => AlgorithmName::Ed25519,
      DhP256HkdfSha256::KEM_ID => AlgorithmName::EcdsaP256Sha256,
      _ => unreachable!(),
    }
  }
  /// Get the length of the contents
  pub(crate) fn len(&self) -> usize {
    2 + 2 + self.public_key.len()
  }
}

impl Serialize for &HttpSigPkConfigContents {
  type Error = HttpSigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), HttpSigError> {
    buf.put_u16(self.alg_id);

    buf.put_u16(to_u16(self.public_key.len())?);
    buf.put(self.public_key.clone());
    Ok(())
  }
}

impl Deserialize for HttpSigPkConfigContents {
  type Error = HttpSigError;
  fn deserialize<B: Buf>(mut buf: &mut B) -> Result<Self, HttpSigError> {
    if buf.remaining() < 2 + 2 + 2 + 2 {
      return Err(HttpSigError::ShortInput);
    }

    let alg_id = buf.get_u16();

    if alg_id != X25519HkdfSha256::KEM_ID && alg_id != DhP256HkdfSha256::KEM_ID {
      return Err(HttpSigError::InvalidParameter);
    }

    let public_key = read_lengthed(&mut buf)?;
    if public_key.len() != 32 && public_key.len() != 65 {
      return Err(HttpSigError::InvalidInputLength);
    }

    Ok(Self { alg_id, public_key })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use bytes::BytesMut;

  #[test]
  fn test_generate_key_pair() {
    let pk_types = vec![HttpSigPkTypes::Ed25519, HttpSigPkTypes::EcdsaP256Sha256];
    for pk_type in pk_types {
      let mut rng = rand::thread_rng();
      let key_pair = pk_type.generate_key_pair(&mut rng);
      assert_eq!(key_pair.public_key.alg_id, pk_type.alg_id());
    }
  }

  #[test]
  fn test_serialize_ph_config() {
    let pk_types = vec![HttpSigPkTypes::Ed25519, HttpSigPkTypes::EcdsaP256Sha256];
    for pk_type in pk_types {
      let mut rng = rand::thread_rng();
      let key_pair = pk_type.generate_key_pair(&mut rng);
      let mut buf = BytesMut::new();
      key_pair.public_key.serialize(&mut buf).unwrap();
      let deserialized = HttpSigPkConfigContents::deserialize(&mut buf.freeze()).unwrap();
      assert_eq!(key_pair.public_key, deserialized);
    }
  }
}
