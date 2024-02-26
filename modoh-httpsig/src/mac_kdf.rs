use crate::{dh::KemKdfDerivedSecret, error::HttpSigError};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;

/// Info for HKDF for derivation of session key
const KDF_INFO: &[u8] = b"session key";

/* ---------------------------------- */
/// Represents a Message Authentication Code (MAC) algorithm with KDF for session key derivation from master secret
pub trait MacKdf {
  /// The algorithm identifier for a KDF implementation
  const MAC_KDF_ID: u16;
  /// Output length for KDF for derive session key
  const KDF_OUTPUT_LEN: usize;
  /// Salt length for HKDF for derive session key
  const KDF_SALT_LEN: usize;
}
/* ---------------------------------- */
#[derive(Clone, Debug, PartialEq, Eq)]
/// HMAC-SHA256 Http signing with session key derivation using HKDF-SHA256 from master secret
pub struct HmacSha256HkdfSha256 {}

impl MacKdf for HmacSha256HkdfSha256 {
  const MAC_KDF_ID: u16 = 0x0001;
  const KDF_OUTPUT_LEN: usize = 32;
  const KDF_SALT_LEN: usize = 32;
}

/* ---------------------------------- */
#[derive(Clone, Debug, PartialEq, Eq)]
/// Session key and nonce derived from master secret
pub struct SessionKeyNonce {
  session_key: Vec<u8>,
  nonce: Vec<u8>,
}
impl SessionKeyNonce {
  /// Get session key
  pub fn session_key(&self) -> &[u8] {
    &self.session_key
  }
  /// Get nonce
  pub fn nonce(&self) -> &[u8] {
    &self.nonce
  }
}
/* ---------------------------------- */
pub trait DeriveSessionKey {
  fn derive_session_key_with_random_nonce<R>(&self, rng: &mut R) -> Result<SessionKeyNonce, HttpSigError>
  where
    R: RngCore + CryptoRng;
  fn derive_session_key_with_nonce(&self, nonce: &[u8]) -> Result<SessionKeyNonce, HttpSigError>;
}
/* ---------------------------------- */
impl DeriveSessionKey for KemKdfDerivedSecret<HmacSha256HkdfSha256> {
  /// Derive session key with random nonce
  fn derive_session_key_with_random_nonce<R>(&self, rng: &mut R) -> Result<SessionKeyNonce, HttpSigError>
  where
    R: RngCore + CryptoRng,
  {
    let mut nonce = vec![0u8; HmacSha256HkdfSha256::KDF_SALT_LEN];
    rng.fill_bytes(&mut nonce);
    let mut session_key = vec![0u8; HmacSha256HkdfSha256::KDF_OUTPUT_LEN];
    Hkdf::<Sha256>::new(Some(&nonce), &self.secret)
      .expand(KDF_INFO, &mut session_key)
      .map_err(|e| HttpSigError::InvalidHkdfLength(e.to_string()))?;
    Ok(SessionKeyNonce { session_key, nonce })
  }

  /// Derive session key with provided nonce
  fn derive_session_key_with_nonce(&self, nonce: &[u8]) -> Result<SessionKeyNonce, HttpSigError> {
    let mut session_key = vec![0u8; HmacSha256HkdfSha256::KDF_OUTPUT_LEN];
    Hkdf::<Sha256>::new(Some(nonce), &self.secret)
      .expand(KDF_INFO, &mut session_key)
      .map_err(|e| HttpSigError::InvalidHkdfLength(e.to_string()))?;
    Ok(SessionKeyNonce {
      session_key,
      nonce: nonce.to_vec(),
    })
  }
}
