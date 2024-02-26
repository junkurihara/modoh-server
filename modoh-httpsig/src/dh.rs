use super::{
  common::*,
  error::HttpSigError,
  mac_kdf::{HmacSha256HkdfSha256, MacKdf},
  HTTPSIG_PROTO_VERSION_DH,
};
use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BufMut, Bytes};
use elliptic_curve::ecdh;
use hpke::{
  generic_array::GenericArray,
  kdf::{extract_and_expand, HkdfSha256, Kdf},
  kem::{DhP256HkdfSha256, Kem, SharedSecret, X25519HkdfSha256},
  Serializable,
};
use rand::{CryptoRng, RngCore};

/* ------------------------------------------- */
#[derive(Clone, Default, Debug, PartialEq, Eq)]
/// Public key, KEM, and KDF types used for Diffie-Hellman key exchange for httpsig's hmac-sha256 signature.
pub enum HttpSigDhTypes {
  #[default]
  /// x25519-hkdf-sha256
  Hs256X25519HkdfSha256,
  /// dhp256-hkdf-sha256
  Hs256DhP256HkdfSha256,
}

impl HttpSigDhTypes {
  /// Get the KEM ID in hpke
  pub(crate) fn kem_id(&self) -> u16 {
    match self {
      HttpSigDhTypes::Hs256X25519HkdfSha256 => X25519HkdfSha256::KEM_ID,
      HttpSigDhTypes::Hs256DhP256HkdfSha256 => DhP256HkdfSha256::KEM_ID,
    }
  }
  /// Get the KDF ID in hpke
  pub(crate) fn kdf_id() -> u16 {
    HkdfSha256::KDF_ID
  }
  /// Get the MAC ID (replacing hpke's AEAD ID)
  pub(crate) fn mac_id() -> u16 {
    HmacSha256HkdfSha256::MAC_KDF_ID
  }
  /// Generate new key pair
  pub(crate) fn generate_key_pair<R>(&self, mut rng: &mut R) -> HttpSigDhKeyPair<HmacSha256HkdfSha256>
  where
    R: RngCore + CryptoRng,
  {
    let (sk_bytes, pk_bytes) = match self {
      HttpSigDhTypes::Hs256X25519HkdfSha256 => {
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
      }
      HttpSigDhTypes::Hs256DhP256HkdfSha256 => {
        let (sk, pk) = DhP256HkdfSha256::gen_keypair(&mut rng);
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
      }
    };

    let contents = HttpSigDhConfigContents {
      kem_id: self.kem_id(),
      kdf_id: Self::kdf_id(),
      mac_kdf_id: Self::mac_id(),
      public_key: pk_bytes.into(),
    };

    HttpSigDhKeyPair {
      private_key: sk_bytes.into(),
      public_key: contents,
      _mac_kdf: std::marker::PhantomData,
    }
  }
}

/* ------------------------------------------- */
#[derive(Clone, Debug, PartialEq, Eq)]
/// Dh key pair for HttpSig HMAC verification
pub(crate) struct HttpSigDhKeyPair<M: MacKdf> {
  private_key: Bytes,
  public_key: HttpSigDhConfigContents,
  _mac_kdf: std::marker::PhantomData<M>,
}

impl<M> HttpSigDhKeyPair<M>
where
  M: MacKdf,
{
  /// Derive hkdf-ed master secret
  pub fn derive_secret(&self, config_other: &HttpSigDhConfigContents) -> Result<KemKdfDerivedSecret<M>, HttpSigError> {
    derive_secret::<M>(config_other, self)
  }
}

/* ------------------------------------------- */
/// Dh configuration contents for HttpSig HMAC verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpSigDhConfigContents {
  pub(crate) kem_id: u16,
  pub(crate) kdf_id: u16,
  pub(crate) mac_kdf_id: u16,
  pub(crate) public_key: Bytes,
}
impl HttpSigDhConfigContents {
  /// Get the length of the contents
  fn len(&self) -> usize {
    2 + 2 + 2 + 2 + self.public_key.len()
  }
  /// Derive hkdf-ed master secret
  pub fn derive_secret<M: MacKdf>(&self, key_pair_self: &HttpSigDhKeyPair<M>) -> Result<KemKdfDerivedSecret<M>, HttpSigError> {
    derive_secret::<M>(self, key_pair_self)
  }
}

impl Serialize for &HttpSigDhConfigContents {
  type Error = HttpSigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), HttpSigError> {
    buf.put_u16(self.kem_id);
    buf.put_u16(self.kdf_id);
    buf.put_u16(self.mac_kdf_id);

    buf.put_u16(to_u16(self.public_key.len())?);
    buf.put(self.public_key.clone());
    Ok(())
  }
}

impl Deserialize for HttpSigDhConfigContents {
  type Error = HttpSigError;
  fn deserialize<B: Buf>(mut buf: &mut B) -> Result<Self, HttpSigError> {
    if buf.remaining() < 2 + 2 + 2 + 2 {
      return Err(HttpSigError::ShortInput);
    }

    let kem_id = buf.get_u16();
    let kdf_id = buf.get_u16();
    let mac_id = buf.get_u16();

    if (kem_id != X25519HkdfSha256::KEM_ID && kem_id != DhP256HkdfSha256::KEM_ID)
      || kdf_id != HkdfSha256::KDF_ID
      || mac_id != HmacSha256HkdfSha256::MAC_KDF_ID
    {
      return Err(HttpSigError::InvalidParameter);
    }

    let public_key = read_lengthed(&mut buf)?;
    if public_key.len() != 32 && public_key.len() != 65 {
      return Err(HttpSigError::InvalidInputLength);
    }

    Ok(Self {
      kem_id,
      kdf_id,
      mac_kdf_id: mac_id,

      public_key,
    })
  }
}

/* ------------------------------------------- */
/// Individual Dh configuration for HttpSig HMAC verification
/// Contains version and dh information. Based on the version specified,
/// the contents can differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpSigDhConfig {
  version: u16,
  length: u16,
  contents: HttpSigDhConfigContents,
}

impl Serialize for &HttpSigDhConfig {
  type Error = HttpSigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), HttpSigError> {
    buf.put_u16(self.version);
    buf.put_u16(self.length);
    self.contents.serialize(buf)
  }
}

impl Deserialize for HttpSigDhConfig {
  type Error = HttpSigError;
  fn deserialize<B: Buf>(mut buf: &mut B) -> Result<Self, Self::Error> {
    if buf.remaining() < 2 {
      return Err(HttpSigError::ShortInput);
    }
    let version = buf.get_u16();
    let mut contents = read_lengthed(&mut buf)?;
    let length = contents.len() as u16;

    Ok(Self {
      version,
      length,
      contents: parse(&mut contents)?,
    })
  }
}

impl From<HttpSigDhConfig> for HttpSigDhConfigContents {
  fn from(c: HttpSigDhConfig) -> Self {
    c.contents
  }
}

impl From<HttpSigDhConfigContents> for HttpSigDhConfig {
  fn from(c: HttpSigDhConfigContents) -> Self {
    Self {
      version: HTTPSIG_PROTO_VERSION_DH,
      length: c.len() as u16,
      contents: c,
    }
  }
}

// // TODO: これら以下は、DHとPKとを共通化して実装するように変更
// /* ------------------------------------------- */
// /// Current Dh configuration served at the endpoint
// /// This is actually imported from odoh_rs::ObliviousDoHConfigs
// pub(crate) struct HttpSigDhConfigs {
//   configs: Vec<HttpSigDhConfig>,
// }

// impl HttpSigDhConfigs {
//   /// Filter the list of configs, leave ones matches HTTPSIG_DH_VERSION.
//   pub fn supported(self) -> Vec<HttpSigDhConfig> {
//     self.into_iter().collect()
//   }
// }

// type VecIter = std::vec::IntoIter<HttpSigDhConfig>;
// impl IntoIterator for HttpSigDhConfigs {
//   type Item = HttpSigDhConfig;
//   type IntoIter = std::iter::Filter<VecIter, fn(&Self::Item) -> bool>;

//   fn into_iter(self) -> Self::IntoIter {
//     self.configs.into_iter().filter(|c| c.version == HTTPSIG_PROTO_VERSION_DH)
//   }
// }

// impl From<Vec<HttpSigDhConfig>> for HttpSigDhConfigs {
//   fn from(configs: Vec<HttpSigDhConfig>) -> Self {
//     Self { configs }
//   }
// }

// impl Serialize for &HttpSigDhConfigs {
//   type Error = HttpSigError;
//   fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), HttpSigError> {
//     // calculate total length
//     let mut len = 0;
//     for c in self.configs.iter() {
//       // 2 bytes of version and 2 bytes of length
//       len += 2 + 2 + c.length;
//     }

//     buf.put_u16(len);
//     for c in self.configs.iter() {
//       c.serialize(buf)?;
//     }

//     Ok(())
//   }
// }

// impl Deserialize for HttpSigDhConfigs {
//   type Error = HttpSigError;
//   fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, HttpSigError> {
//     let mut buf = read_lengthed(buf)?;

//     let mut configs = Vec::new();
//     loop {
//       if buf.is_empty() {
//         break;
//       }
//       let c = parse(&mut buf)?;
//       configs.push(c);
//     }

//     Ok(Self { configs })
//   }
// }

// /* ------------------------------------------- */
// #[derive(Clone, Debug, PartialEq, Eq)]
// /// Dh public keys for HttpSig HMAC verification
// pub struct HttpSigDhPublicKeys<M: Mac> {
//   key_pairs: Vec<HttpSigDhKeyPair<M>>,
//   serialized_configs: Vec<u8>,
// }

// impl<M> HttpSigDhPublicKeys<M>
// where
//   M: Mac,
// {
//   /// Create a new Dh public keys for HttpSig HMAC verification
//   pub fn new(dh_types: &[HttpSigDhTypes]) -> Result<Self, HttpSigError> {
//     let key_pairs = dh_types
//       .iter()
//       .map(|t| {
//         let mut rng = rand::thread_rng();
//         t.generate_key_pair(&mut rng)
//       })
//       .collect::<Vec<_>>();

//     let configs = key_pairs
//       .iter()
//       .map(|k| HttpSigDhConfig::from(k.public_key.clone()))
//       .collect::<Vec<_>>();

//     let mut serialized_configs = Vec::new();
//     HttpSigDhConfigs::from(configs).serialize(&mut serialized_configs)?;
//     Ok(Self {
//       key_pairs,
//       serialized_configs,
//     })
//   }
// }

/* ------------------------------------------- */
/// Imported from `rust-hpke`
/// Represents a ciphersuite context. That's "KEMXX", where `XX` is the KEM ID
pub(crate) type KemSuiteId = [u8; 5];
/// Imported from `rust-hpke`
/// Constructs the `suite_id` used as binding context in all functions in `kem`
pub(crate) fn kem_suite_id<Kem: hpke::Kem>() -> KemSuiteId {
  // XX is the KEM ID
  let mut suite_id = *b"KEMXX";

  // Write the KEM ID to the buffer. Forgive the explicit indexing.
  BigEndian::write_u16(&mut suite_id[3..5], Kem::KEM_ID);

  suite_id
}
pub(crate) struct KemKdfDerivedSecret<M>
where
  M: MacKdf,
{
  pub(crate) secret: Vec<u8>,
  _mac_kdf: std::marker::PhantomData<M>,
}

/// Derive the master secret from the other's public key and my secret key with DH-Kex,
/// and extract-then-expand with HKDF exactly similar to that in HPKE.
/// In HPKE, kem_context fed into HKDF as nonce is kem_context = encapped_key || pk_recip || pk_sender_id.
/// In our 'non-directional' case (no `sender` or `recipient`), we can use encapped_key ^ pk_recip,
/// i.e., XOR of your_pk and my_pk, as kem_context.
pub fn derive_secret<M: MacKdf>(
  config_other: &HttpSigDhConfigContents,
  key_pair_self: &HttpSigDhKeyPair<M>,
) -> Result<KemKdfDerivedSecret<M>, HttpSigError> {
  if config_other.kem_id != key_pair_self.public_key.kem_id {
    return Err(HttpSigError::InvalidParameter);
  }
  if config_other.public_key.len() != key_pair_self.public_key.public_key.len() {
    return Err(HttpSigError::InvalidInputLength);
  }

  let mut kem_context = config_other.public_key.to_vec();
  kem_context
    .iter_mut()
    .zip(key_pair_self.public_key.public_key.iter())
    .for_each(|(a, b)| {
      *a ^= b;
    });

  let raw_secret_bytes = match config_other.kem_id {
    X25519HkdfSha256::KEM_ID => {
      let suite_id = kem_suite_id::<X25519HkdfSha256>();
      let your_pk = ed25519_compact::x25519::PublicKey::from_slice(&config_other.public_key).unwrap();
      let my_sk = ed25519_compact::x25519::SecretKey::from_slice(&key_pair_self.private_key).unwrap();
      let kex_res = your_pk.dh(&my_sk)?.to_vec();
      let mut buf = <SharedSecret<X25519HkdfSha256> as Default>::default();
      let _ = extract_and_expand::<HkdfSha256>(kex_res.as_slice(), &suite_id, &kem_context, &mut buf.0);
      buf.0.to_vec()
    }
    DhP256HkdfSha256::KEM_ID => {
      let suite_id = kem_suite_id::<DhP256HkdfSha256>();
      let your_pk = p256::PublicKey::from_sec1_bytes(&config_other.public_key)?;
      let my_sk = p256::SecretKey::from_bytes(&GenericArray::clone_from_slice(&key_pair_self.private_key))?;
      let kex_res = ecdh::diffie_hellman(my_sk.to_nonzero_scalar(), your_pk.as_affine());

      let mut buf = <SharedSecret<DhP256HkdfSha256> as Default>::default();
      let _ = extract_and_expand::<HkdfSha256>(kex_res.raw_secret_bytes(), &suite_id, &kem_context, &mut buf.0);
      buf.0.to_vec()
    }
    _ => unreachable!(),
  };

  Ok(KemKdfDerivedSecret {
    secret: raw_secret_bytes,
    _mac_kdf: std::marker::PhantomData,
  })
}

/* ------------------------------------------- */

#[cfg(test)]
mod tests {
  use super::super::mac_kdf::DeriveSessionKey;
  use super::*;
  use rand::thread_rng;

  #[test]
  fn test_generate_key_pair() {
    let x25519 = HttpSigDhTypes::Hs256X25519HkdfSha256.generate_key_pair(&mut thread_rng());
    let dhp256 = HttpSigDhTypes::Hs256DhP256HkdfSha256.generate_key_pair(&mut thread_rng());

    assert_eq!(x25519.private_key.len(), 32);
    assert_eq!(x25519.public_key.kem_id, X25519HkdfSha256::KEM_ID);
    assert_eq!(x25519.public_key.kdf_id, HkdfSha256::KDF_ID);
    assert_eq!(x25519.public_key.mac_kdf_id, HmacSha256HkdfSha256::MAC_KDF_ID);
    assert_eq!(x25519.public_key.public_key.len(), 32);

    assert_eq!(dhp256.private_key.len(), 32);
    assert_eq!(dhp256.public_key.kem_id, DhP256HkdfSha256::KEM_ID);
    assert_eq!(dhp256.public_key.kdf_id, HkdfSha256::KDF_ID);
    assert_eq!(dhp256.public_key.mac_kdf_id, HmacSha256HkdfSha256::MAC_KDF_ID);
    assert_eq!(dhp256.public_key.public_key.len(), 65);
  }

  // #[test]
  // fn test_generate_new_configs() {
  //   let dh_types = vec![HttpSigDhTypes::Hs256X25519HkdfSha256, HttpSigDhTypes::Hs256DhP256HkdfSha256];

  //   // let keys = HttpSigDhPublicKeys::new(&dh_types).unwrap();
  //   // assert_eq!(keys.key_pairs.len(), 2);
  //   // assert_eq!(
  //   //   keys.serialized_configs.len(),
  //   //   2 + (4 + 2 + 2 + 2 + 2 + 32) + (4 + 2 + 2 + 2 + 2 + 65)
  //   // );

  //   // let serialized = keys.serialized_configs.clone();
  //   // let deserialized = HttpSigDhConfigs::deserialize(&mut Bytes::from(serialized)).unwrap();
  //   // assert_eq!(keys.key_pairs.len(), deserialized.configs.len());
  //   // assert_eq!(keys.key_pairs[0].public_key, deserialized.configs[0].contents);
  //   // assert_eq!(keys.key_pairs[1].public_key, deserialized.configs[1].contents);
  // }

  #[test]
  fn test_derive_secret() {
    let dh_types = vec![HttpSigDhTypes::Hs256DhP256HkdfSha256, HttpSigDhTypes::Hs256X25519HkdfSha256];
    dh_types.iter().for_each(|t| {
      let alice_kp = t.generate_key_pair(&mut thread_rng());
      let bob_kp = t.generate_key_pair(&mut thread_rng());

      let shared_1 = alice_kp.derive_secret(&bob_kp.public_key).unwrap();
      let shared_2 = bob_kp.derive_secret(&alice_kp.public_key).unwrap();
      assert_eq!(shared_1.secret, shared_2.secret);

      let shared_1 = alice_kp.public_key.derive_secret(&bob_kp).unwrap();
      let shared_2 = bob_kp.public_key.derive_secret(&alice_kp).unwrap();
      assert_eq!(shared_1.secret, shared_2.secret);
      let session_key_1 = shared_1.derive_session_key_with_random_nonce(&mut thread_rng()).unwrap();
      let session_key_2 = shared_2.derive_session_key_with_nonce(session_key_1.nonce()).unwrap();
      assert_eq!(session_key_1.session_key(), session_key_2.session_key());
      assert_eq!(session_key_1.nonce(), session_key_2.nonce());
    })
  }

  #[test]
  fn test_serialize_dh_config() {
    let dh_types = vec![HttpSigDhTypes::Hs256DhP256HkdfSha256, HttpSigDhTypes::Hs256X25519HkdfSha256];
    dh_types.iter().for_each(|t| {
      let kp = t.generate_key_pair(&mut thread_rng());
      let mut serialized_config = Vec::new();
      kp.public_key.serialize(&mut serialized_config).unwrap();

      let deserialized = HttpSigDhConfigContents::deserialize(&mut Bytes::from(serialized_config)).unwrap();

      assert_eq!(kp.public_key, deserialized);
    })
  }
}
