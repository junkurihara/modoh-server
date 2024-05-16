use super::{
  common::*,
  error::HttpSigError,
  mac_kdf::{HmacSha256HkdfSha256, MacKdf},
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
pub struct HttpSigDhKeyPair<M: MacKdf> {
  pub(super) private_key: Bytes,
  pub(super) public_key: HttpSigDhConfigContents,
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
  /// Check if the same kem-kdf-mac is used
  pub fn is_same_kem_kdf_mac(&self, other: &HttpSigDhConfigContents) -> bool {
    self.public_key.kem_id == other.kem_id
      && self.public_key.kdf_id == other.kdf_id
      && self.public_key.mac_kdf_id == other.mac_kdf_id
  }
}

/* ------------------------------------------- */
/// Dh configuration contents for HttpSig HMAC verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSigDhConfigContents {
  pub(crate) kem_id: u16,
  pub(crate) kdf_id: u16,
  pub(crate) mac_kdf_id: u16,
  pub(crate) public_key: Bytes,
}
impl HttpSigDhConfigContents {
  /// Get the length of the contents
  pub(crate) fn len(&self) -> usize {
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemKdfDerivedSecret<M>
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
      let _ = extract_and_expand::<HkdfSha256>(kex_res.raw_secret_bytes().as_slice(), &suite_id, &kem_context, &mut buf.0);
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

  #[test]
  fn test_derive_secret() {
    let dh_types = [HttpSigDhTypes::Hs256DhP256HkdfSha256, HttpSigDhTypes::Hs256X25519HkdfSha256];
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
    let dh_types = [HttpSigDhTypes::Hs256DhP256HkdfSha256, HttpSigDhTypes::Hs256X25519HkdfSha256];
    dh_types.iter().for_each(|t| {
      let kp = t.generate_key_pair(&mut thread_rng());
      let mut serialized_config = Vec::new();
      kp.public_key.serialize(&mut serialized_config).unwrap();

      let deserialized = HttpSigDhConfigContents::deserialize(&mut Bytes::from(serialized_config)).unwrap();

      assert_eq!(kp.public_key, deserialized);
    })
  }
}
