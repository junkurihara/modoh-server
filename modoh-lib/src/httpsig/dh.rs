use super::error::HttpSigDhError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use hpke::{
  kdf::{HkdfSha256, Kdf},
  kem::{DhP256HkdfSha256, Kem, X25519HkdfSha256},
  Serializable,
};
use rand::{CryptoRng, RngCore};

/// HttpSigDh version supported by this library
pub const HTTPSIG_DH_VERSION: u16 = 0x0001;

/* ------------------------------------------- */
// Imported from odoh-rs crate

/// Serialize to IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
trait Serialize {
  type Error;
  /// Serialize the provided struct into the buf.
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), Self::Error>;
}

/// Deserialize from IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
trait Deserialize {
  type Error;
  /// Deserialize a struct from the buf.
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>
  where
    Self: Sized;
}

/// Convenient function to deserialize a structure from Bytes.
fn parse<D: Deserialize, B: Buf>(buf: &mut B) -> Result<D, D::Error> {
  D::deserialize(buf)
}

/// Convenient function to serialize a structure into a new BytesMut.
fn compose<S: Serialize>(s: S) -> Result<BytesMut, S::Error> {
  let mut buf = BytesMut::new();
  s.serialize(&mut buf)?;
  Ok(buf)
}

fn read_lengthed<B: Buf>(b: &mut B) -> Result<Bytes, HttpSigDhError> {
  if b.remaining() < 2 {
    return Err(HttpSigDhError::ShortInput);
  }

  let len = b.get_u16() as usize;

  if len > b.remaining() {
    return Err(HttpSigDhError::InvalidInputLength);
  }

  Ok(b.copy_to_bytes(len))
}

#[inline]
fn to_u16(n: usize) -> Result<u16, HttpSigDhError> {
  n.try_into().map_err(|_| HttpSigDhError::InvalidInputLength)
}

/* ------------------------------------------- */
#[derive(Clone, Default, Debug, PartialEq, Eq)]
/// Public key, KEM, and KDF types used for Diffie-Hellman key exchange for httpsig's hmac-sha256 signature.
pub enum HttpSigDhTypes {
  #[default]
  /// x25519-hkdf-sha256
  X25519HkdfSha256,
  /// dhp256-hkdf-sha256
  DhP256HkdfSha256,
}

impl HttpSigDhTypes {
  /// Get the KEM ID in hpke
  pub(crate) fn kem_id(&self) -> u16 {
    match self {
      HttpSigDhTypes::X25519HkdfSha256 => X25519HkdfSha256::KEM_ID,
      HttpSigDhTypes::DhP256HkdfSha256 => DhP256HkdfSha256::KEM_ID,
    }
  }
  /// Get the KDF ID in hpke
  pub(crate) fn kdf_id() -> u16 {
    HkdfSha256::KDF_ID
  }
  /// Generate new key pair
  pub(crate) fn generate_key_pair<R>(&self, mut rng: &mut R) -> HttpSigDhKeyPair
  where
    R: RngCore + CryptoRng,
  {
    let (sk_bytes, pk_bytes) = match self {
      HttpSigDhTypes::X25519HkdfSha256 => {
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
      }
      HttpSigDhTypes::DhP256HkdfSha256 => {
        let (sk, pk) = DhP256HkdfSha256::gen_keypair(&mut rng);
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
      }
    };

    let contents = HttpSigDhConfigContents {
      kem_id: self.kem_id(),
      kdf_id: Self::kdf_id(),
      public_key: pk_bytes.into(),
    };

    HttpSigDhKeyPair {
      private_key: sk_bytes.into(),
      public_key: contents,
    }
  }
}

impl TryFrom<&str> for HttpSigDhTypes {
  type Error = anyhow::Error;

  fn try_from(s: &str) -> Result<Self, Self::Error> {
    match s {
      "x25519-hkdf-sha256" => Ok(HttpSigDhTypes::X25519HkdfSha256),
      "dhp256-hkdf-sha256" => Ok(HttpSigDhTypes::DhP256HkdfSha256),
      _ => Err(anyhow::anyhow!("Invalid DhKemTypes: {}", s)),
    }
  }
}

impl std::fmt::Display for HttpSigDhTypes {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      HttpSigDhTypes::X25519HkdfSha256 => write!(f, "x25519-hkdf-sha256"),
      HttpSigDhTypes::DhP256HkdfSha256 => write!(f, "dhp256-hkdf-sha256"),
    }
  }
}

/* ------------------------------------------- */
#[derive(Clone, Debug, PartialEq, Eq)]
/// Dh key pair for HttpSig HMAC verification
pub(crate) struct HttpSigDhKeyPair {
  private_key: Bytes,
  public_key: HttpSigDhConfigContents,
}

/* ------------------------------------------- */
/// Dh configuration contents for HttpSig HMAC verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpSigDhConfigContents {
  pub(crate) kem_id: u16,
  pub(crate) kdf_id: u16,
  pub(crate) public_key: Bytes,
}
impl HttpSigDhConfigContents {
  /// Get the length of the contents
  fn len(&self) -> usize {
    2 + 2 + 2 + self.public_key.len()
  }
}

impl Serialize for &HttpSigDhConfigContents {
  type Error = HttpSigDhError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), HttpSigDhError> {
    buf.put_u16(self.kem_id);
    buf.put_u16(self.kdf_id);

    buf.put_u16(to_u16(self.public_key.len())?);
    buf.put(self.public_key.clone());
    Ok(())
  }
}

impl Deserialize for HttpSigDhConfigContents {
  type Error = HttpSigDhError;
  fn deserialize<B: Buf>(mut buf: &mut B) -> Result<Self, HttpSigDhError> {
    if buf.remaining() < 2 + 2 + 2 {
      return Err(HttpSigDhError::ShortInput);
    }

    let kem_id = buf.get_u16();
    let kdf_id = buf.get_u16();

    if (kem_id != X25519HkdfSha256::KEM_ID && kem_id != DhP256HkdfSha256::KEM_ID) || kdf_id != HkdfSha256::KDF_ID {
      return Err(HttpSigDhError::InvalidParameter);
    }

    let public_key = read_lengthed(&mut buf)?;
    if public_key.len() != 32 && public_key.len() != 65 {
      return Err(HttpSigDhError::InvalidInputLength);
    }

    Ok(Self {
      kem_id,
      kdf_id,

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
  type Error = HttpSigDhError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), HttpSigDhError> {
    buf.put_u16(self.version);
    buf.put_u16(self.length);
    self.contents.serialize(buf)
  }
}

impl Deserialize for HttpSigDhConfig {
  type Error = HttpSigDhError;
  fn deserialize<B: Buf>(mut buf: &mut B) -> Result<Self, Self::Error> {
    if buf.remaining() < 2 {
      return Err(HttpSigDhError::ShortInput);
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
      version: HTTPSIG_DH_VERSION,
      length: c.len() as u16,
      contents: c,
    }
  }
}

/* ------------------------------------------- */
/// Current Dh configuration served at the endpoint
/// This is actually imported from odoh_rs::ObliviousDoHConfigs
pub(crate) struct HttpSigDhConfigs {
  configs: Vec<HttpSigDhConfig>,
}

impl HttpSigDhConfigs {
  /// Filter the list of configs, leave ones matches HTTPSIG_DH_VERSION.
  pub fn supported(self) -> Vec<HttpSigDhConfig> {
    self.into_iter().collect()
  }
}

type VecIter = std::vec::IntoIter<HttpSigDhConfig>;
impl IntoIterator for HttpSigDhConfigs {
  type Item = HttpSigDhConfig;
  type IntoIter = std::iter::Filter<VecIter, fn(&Self::Item) -> bool>;

  fn into_iter(self) -> Self::IntoIter {
    self.configs.into_iter().filter(|c| c.version == HTTPSIG_DH_VERSION)
  }
}

impl From<Vec<HttpSigDhConfig>> for HttpSigDhConfigs {
  fn from(configs: Vec<HttpSigDhConfig>) -> Self {
    Self { configs }
  }
}

impl Serialize for &HttpSigDhConfigs {
  type Error = HttpSigDhError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), HttpSigDhError> {
    // calculate total length
    let mut len = 0;
    for c in self.configs.iter() {
      // 2 bytes of version and 2 bytes of length
      len += 2 + 2 + c.length;
    }

    buf.put_u16(len);
    for c in self.configs.iter() {
      c.serialize(buf)?;
    }

    Ok(())
  }
}

impl Deserialize for HttpSigDhConfigs {
  type Error = HttpSigDhError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, HttpSigDhError> {
    let mut buf = read_lengthed(buf)?;

    let mut configs = Vec::new();
    loop {
      if buf.is_empty() {
        break;
      }
      let c = parse(&mut buf)?;
      configs.push(c);
    }

    Ok(Self { configs })
  }
}

/* ------------------------------------------- */
#[derive(Clone, Debug, PartialEq, Eq)]
/// Dh public keys for HttpSig HMAC verification
pub struct HttpSigDhPublicKeys {
  key_pairs: Vec<HttpSigDhKeyPair>,
  serialized_configs: Vec<u8>,
}

impl HttpSigDhPublicKeys {
  /// Create a new Dh public keys for HttpSig HMAC verification
  pub fn new(dh_types: &[HttpSigDhTypes]) -> Result<Self, HttpSigDhError> {
    let key_pairs = dh_types
      .iter()
      .map(|t| {
        let mut rng = rand::thread_rng();
        t.generate_key_pair(&mut rng)
      })
      .collect::<Vec<_>>();

    let configs = key_pairs
      .iter()
      .map(|k| HttpSigDhConfig::from(k.public_key.clone()))
      .collect::<Vec<_>>();

    let mut serialized_configs = Vec::new();
    HttpSigDhConfigs::from(configs).serialize(&mut serialized_configs)?;
    Ok(Self {
      key_pairs,
      serialized_configs,
    })
  }
}

/* ------------------------------------------- */
/// TODO:!
/// TODO:!
pub fn derive_secret(
  config_other: &HttpSigDhConfigContents,
  key_pair_self: &HttpSigDhKeyPair,
) -> Result<Vec<u8>, HttpSigDhError> {
  use hpke::Deserializable;
  let mut out_buf = vec![0u8; 32];
  let res = match config_other.kem_id {
    X25519HkdfSha256::KEM_ID => {
      todo!()
    }
    DhP256HkdfSha256::KEM_ID => {
      assert_eq!(config_other.kem_id, key_pair_self.public_key.kem_id);

      // let your_pk = p256::PublicKey::from_sec1_bytes(&destination_config.public_key).unwrap();
      // let my_sk_bytes = hpke::generic_array::GenericArray::clone_from_slice(&source_key_pair.private_key);
      // let my_sk = p256::SecretKey::from_bytes(&my_sk_bytes).unwrap();
      // let kex_res = elliptic_curve::ecdh::diffie_hellman(my_sk.to_nonzero_scalar(), your_pk.as_affine());

      // let mut buf = <hpke::kem::SharedSecret<DhP256HkdfSha256> as Default>::default();
      // let _ = hpke::kdf::extract_and_expand::<HkdfSha256>(kex_res.raw_secret_bytes(), b"", b"", &mut buf.0);
      // out_buf.copy_from_slice(&buf.0);
      // // out_buf.copy_from_slice(&kex_res[..32]);
      // Ok(()) as Result<(), HttpSigDhError>
      // TODO: HPKEだとdecap内において、kem_contextにencapped keyを記録してkdfを通さなければならないが、今回は双方向になるのでencapped keyがsenderのpkと言えなくなる。そうなると、HPKEのkem_contextの仕様を変えないとKDFのsaltないのserializeが混乱する。
      // あるいは、登り下りで別のshared secretを利用するのが無難か。。。？

      let your_pk = <DhP256HkdfSha256 as Kem>::EncappedKey::from_bytes(&config_other.public_key).unwrap();
      let my_sk = <DhP256HkdfSha256 as Kem>::PrivateKey::from_bytes(&key_pair_self.private_key).unwrap();
      // let recv_ctx = hpke::setup_receiver::<hpke::aead::ExportOnlyAead, hpke::kdf::HkdfSha256, hpke::kem::DhP256HkdfSha256>(
      //   &hpke::OpModeR::Base,
      //   &my_sk,
      //   &your_pk,
      //   b"",
      // )
      // .unwrap();
      // recv_ctx.export(b"", &mut out_buf)
      let decapped = <DhP256HkdfSha256 as Kem>::decap(&my_sk, None, &your_pk).unwrap();
      let decapped = decapped.0.to_vec();
      out_buf.copy_from_slice(&decapped);
      Ok(()) as Result<(), HttpSigDhError>
    }
    _ => unreachable!(),
  };
  // assert!(res.is_ok());

  // expand with hkdf and random salt, salt must be included in the nonce field at the http signature-input header

  Ok(out_buf)

  // let kdf = HkdfSha256::default();
  // let suite = hpke::Suite::new(kem, kdf);

  // let secret = suite.derive_secret(&config.public_key, b"eae_prk", b"", 32).unwrap();
  // println!("{:?}", secret);
}

/* ------------------------------------------- */

#[cfg(test)]
mod tests {
  use super::*;
  use rand::thread_rng;

  #[test]
  fn test_generate_key_pair() {
    let x25519 = HttpSigDhTypes::X25519HkdfSha256.generate_key_pair(&mut thread_rng());
    let dhp256 = HttpSigDhTypes::DhP256HkdfSha256.generate_key_pair(&mut thread_rng());

    assert_eq!(x25519.private_key.len(), 32);
    assert_eq!(x25519.public_key.kem_id, X25519HkdfSha256::KEM_ID);
    assert_eq!(x25519.public_key.kdf_id, HkdfSha256::KDF_ID);
    assert_eq!(x25519.public_key.public_key.len(), 32);

    assert_eq!(dhp256.private_key.len(), 32);
    assert_eq!(dhp256.public_key.kem_id, DhP256HkdfSha256::KEM_ID);
    assert_eq!(dhp256.public_key.kdf_id, HkdfSha256::KDF_ID);
    assert_eq!(dhp256.public_key.public_key.len(), 65);
  }

  #[test]
  fn test_generate_new_configs() {
    let dh_types = vec![HttpSigDhTypes::X25519HkdfSha256, HttpSigDhTypes::DhP256HkdfSha256];
    let keys = HttpSigDhPublicKeys::new(&dh_types).unwrap();
    assert_eq!(keys.key_pairs.len(), 2);
    assert_eq!(keys.serialized_configs.len(), 2 + (4 + 2 + 2 + 2 + 32) + (4 + 2 + 2 + 2 + 65));

    let serialized = keys.serialized_configs.clone();
    let deserialized = HttpSigDhConfigs::deserialize(&mut Bytes::from(serialized)).unwrap();
    assert_eq!(keys.key_pairs.len(), deserialized.configs.len());
    assert_eq!(keys.key_pairs[0].public_key, deserialized.configs[0].contents);
    assert_eq!(keys.key_pairs[1].public_key, deserialized.configs[1].contents);
  }

  #[test]
  fn test_derive_secret() {
    let dh_types = vec![HttpSigDhTypes::DhP256HkdfSha256];
    let alice_keys = HttpSigDhPublicKeys::new(&dh_types).unwrap();
    let bob_keys = HttpSigDhPublicKeys::new(&dh_types).unwrap();
    // println!("{:#?}", alice_keys);
    // println!(
    //   "serialized in vec: {:?}",
    //   alice_keys.key_pairs[0].public_key.public_key.to_vec()
    // );
    // println!("{:#?}", bob_keys);
    // println!(
    //   "serialized in vec: {:?}",
    //   bob_keys.key_pairs[0].public_key.public_key.to_vec()
    // );

    let alice_sk = &alice_keys.key_pairs[0];
    let bob_pk = &bob_keys.key_pairs[0].public_key;

    let shared_1 = derive_secret(bob_pk, alice_sk).unwrap();

    let bob_sk = &bob_keys.key_pairs[0];
    let alice_pk = &alice_keys.key_pairs[0].public_key;

    let shared_2 = derive_secret(alice_pk, bob_sk).unwrap();

    assert_eq!(shared_1, shared_2);
    println!("{:?}", shared_1);
    println!("{:?}", shared_2);
  }
}
