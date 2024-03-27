use bytes::{Buf, BufMut};
use common::{parse, read_lengthed};

mod common;
mod dh;
mod error;
mod mac_kdf;
mod pk;

pub use common::{Deserialize, Serialize};
pub use dh::{HttpSigDhConfigContents, HttpSigDhKeyPair, HttpSigDhTypes, KemKdfDerivedSecret};
pub use error::HttpSigError;
pub use mac_kdf::{DeriveKeyId, DeriveSessionKey, HmacSha256HkdfSha256, SessionKeyNonce};
pub use pk::{HttpSigPkConfigContents, HttpSigPkKeyPair, HttpSigPkTypes};

/// HttpSig key version for MAC via DH supported by this library
pub const HTTPSIG_PROTO_VERSION_DH: u16 = 0x0010;
/// HttpSig key version for public key signature supported by this library
pub const HTTPSIG_PROTO_VERSION_PK: u16 = 0x0020;

/* ------------------------------------------- */
#[derive(Clone, Default, Debug, PartialEq, Eq)]
/// Key types used for httpsig verification
/// - Asymmetric key for public-key-based signature like ed25519, ecdsa-p256-sha256 (es256).
/// - Asymmetric key to perform Diffie-Hellman key exchange for hmac-sha256 (hs256) signature.
/// These are automatically generated and exposed at `/.well-known/httpsigconfigs` endpoint.
///   default = ["hs256-x25519-hkdf-sha256"],
///  supported = "hs256-p256-hkdf-sha256" (hmac-sha256 with hkdf via ecdh), "hs256-x25519-hkdf-sha256" (hmac-sha256 with hkdf via ecdh), "ed25519", and "es256"
pub enum HttpSigKeyTypes {
  #[default]
  /// hs256-x25519-hkdf-sha256
  Hs256X25519HkdfSha256,
  /// hs256-p256-hkdf-sha256
  Hs256P256HkdfSha256,
  /// ed25519
  Ed25519,
  /// es256
  Es256,
}

impl TryFrom<&str> for HttpSigKeyTypes {
  type Error = anyhow::Error;

  fn try_from(s: &str) -> Result<Self, Self::Error> {
    match s {
      "hs256-x25519-hkdf-sha256" => Ok(HttpSigKeyTypes::Hs256X25519HkdfSha256),
      "hs256-p256-hkdf-sha256" => Ok(HttpSigKeyTypes::Hs256P256HkdfSha256),
      "ed25519" => Ok(HttpSigKeyTypes::Ed25519),
      "es256" => Ok(HttpSigKeyTypes::Es256),
      _ => Err(anyhow::anyhow!("Invalid KeyTypes: {}", s)),
    }
  }
}

impl std::fmt::Display for HttpSigKeyTypes {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      HttpSigKeyTypes::Hs256X25519HkdfSha256 => write!(f, "hs256-x25519-hkdf-sha256"),
      HttpSigKeyTypes::Hs256P256HkdfSha256 => write!(f, "hs256-p256-hkdf-sha256"),
      HttpSigKeyTypes::Ed25519 => write!(f, "ed25519"),
      HttpSigKeyTypes::Es256 => write!(f, "es256"),
    }
  }
}

/* ------------------------------------------- */
/// Individual configuration for HttpSig hmac/public key signature verification
/// Contains version and dh/pk information. Based on the version specified,
/// the contents can differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSigConfig {
  version: u16,
  length: u16,
  pub contents: HttpSigConfigContents,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpSigConfigContents {
  Dh(HttpSigDhConfigContents),
  Pk(HttpSigPkConfigContents),
}

impl Serialize for &HttpSigConfig {
  type Error = HttpSigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), HttpSigError> {
    buf.put_u16(self.version);
    buf.put_u16(self.length);
    match &self.contents {
      HttpSigConfigContents::Dh(c) => c.serialize(buf),
      HttpSigConfigContents::Pk(c) => c.serialize(buf),
    }
  }
}

impl Deserialize for HttpSigConfig {
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
      contents: match version {
        HTTPSIG_PROTO_VERSION_DH => HttpSigConfigContents::Dh(parse(&mut contents)?),
        HTTPSIG_PROTO_VERSION_PK => HttpSigConfigContents::Pk(parse(&mut contents)?),
        _ => return Err(HttpSigError::InvalidParameter),
      },
    })
  }
}

impl From<HttpSigConfig> for HttpSigConfigContents {
  fn from(c: HttpSigConfig) -> Self {
    c.contents
  }
}

impl From<HttpSigConfigContents> for HttpSigConfig {
  fn from(c: HttpSigConfigContents) -> Self {
    let version = match &c {
      HttpSigConfigContents::Dh(_) => HTTPSIG_PROTO_VERSION_DH,
      HttpSigConfigContents::Pk(_) => HTTPSIG_PROTO_VERSION_PK,
    };
    let length = match &c {
      HttpSigConfigContents::Dh(c) => c.len() as u16,
      HttpSigConfigContents::Pk(c) => c.len() as u16,
    };
    Self {
      version,
      length,
      contents: c,
    }
  }
}

/* ------------------------------------------- */
#[derive(Clone, Debug, PartialEq, Eq)]
/// Current Dh configuration served at the endpoint
/// This is actually imported from odoh_rs::ObliviousDoHConfigs
pub struct HttpSigConfigs {
  configs: Vec<HttpSigConfig>,
}

#[allow(unused)]
impl HttpSigConfigs {
  /// Filter the list of configs, leave ones matches HTTPSIG_DH_VERSION.
  pub fn supported(self) -> Vec<HttpSigConfig> {
    self.into_iter().collect()
  }
}

type VecIter = std::vec::IntoIter<HttpSigConfig>;
impl IntoIterator for HttpSigConfigs {
  type Item = HttpSigConfig;
  type IntoIter = std::iter::Filter<VecIter, fn(&Self::Item) -> bool>;

  fn into_iter(self) -> Self::IntoIter {
    self
      .configs
      .into_iter()
      .filter(|c| c.version == HTTPSIG_PROTO_VERSION_DH || c.version == HTTPSIG_PROTO_VERSION_PK)
  }
}

impl From<Vec<HttpSigConfig>> for HttpSigConfigs {
  fn from(configs: Vec<HttpSigConfig>) -> Self {
    Self { configs }
  }
}

impl Serialize for &HttpSigConfigs {
  type Error = HttpSigError;
  fn serialize<B: BufMut>(self, buf: &mut B) -> Result<(), HttpSigError> {
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

impl Deserialize for HttpSigConfigs {
  type Error = HttpSigError;
  fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, HttpSigError> {
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
/// Public keys for HttpSig HMAC verification
pub struct HttpSigPublicKeys {
  key_pairs: Vec<HttpSigKeyPair>,
  serialized_configs: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpSigKeyPair {
  Dh(HttpSigDhKeyPair<HmacSha256HkdfSha256>),
  Pk(HttpSigPkKeyPair),
}

impl HttpSigPublicKeys {
  /// Create a new public keys for HttpSig signature/hmac verification
  pub fn new(key_types: &[HttpSigKeyTypes]) -> Result<Self, HttpSigError> {
    let key_pairs = key_types
      .iter()
      .map(|t| {
        let mut rng = rand::thread_rng();
        match t {
          HttpSigKeyTypes::Hs256X25519HkdfSha256 => {
            HttpSigKeyPair::Dh(HttpSigDhTypes::Hs256X25519HkdfSha256.generate_key_pair(&mut rng))
          }
          HttpSigKeyTypes::Hs256P256HkdfSha256 => {
            HttpSigKeyPair::Dh(HttpSigDhTypes::Hs256DhP256HkdfSha256.generate_key_pair(&mut rng))
          }
          HttpSigKeyTypes::Ed25519 => HttpSigKeyPair::Pk(HttpSigPkTypes::Ed25519.generate_key_pair(&mut rng)),
          HttpSigKeyTypes::Es256 => HttpSigKeyPair::Pk(HttpSigPkTypes::EcdsaP256Sha256.generate_key_pair(&mut rng)),
        }
      })
      .collect::<Vec<_>>();

    let configs = key_pairs
      .iter()
      .map(|k| {
        HttpSigConfig::from({
          match k {
            HttpSigKeyPair::Dh(kp) => HttpSigConfigContents::Dh(kp.public_key.clone()),
            HttpSigKeyPair::Pk(kp) => HttpSigConfigContents::Pk(kp.public_key.clone()),
          }
        })
      })
      .collect::<Vec<_>>();

    let mut serialized_configs = Vec::new();
    HttpSigConfigs::from(configs).serialize(&mut serialized_configs)?;
    Ok(Self {
      key_pairs,
      serialized_configs,
    })
  }

  /// Get serialized configs
  pub fn as_config(&self) -> &[u8] {
    &self.serialized_configs
  }
  /// Get serialized configs
  pub fn as_key_pairs(&self) -> &[HttpSigKeyPair] {
    &self.key_pairs
  }
}

/* ------------------------------------------- */
#[cfg(test)]
mod tests {
  use crate::mac_kdf::DeriveSessionKey;

  use super::*;
  use bytes::Bytes;
  #[test]
  fn test_generate_new_configs() {
    let key_types = vec![
      HttpSigKeyTypes::Hs256X25519HkdfSha256,
      HttpSigKeyTypes::Hs256P256HkdfSha256,
      HttpSigKeyTypes::Ed25519,
      HttpSigKeyTypes::Es256,
    ];

    let keys = HttpSigPublicKeys::new(&key_types).unwrap();
    assert_eq!(keys.key_pairs.len(), 4);
    assert_eq!(
      keys.serialized_configs.len(),
      2 + (4 + 2 + 2 + 2 + 2 + 32) + (4 + 2 + 2 + 2 + 2 + 65) + (4 + 2 + 2 + 32) + (4 + 2 + 2 + 65)
    );

    let serialized = keys.serialized_configs.clone();
    let deserialized = HttpSigConfigs::deserialize(&mut Bytes::from(serialized)).unwrap();
    assert_eq!(keys.key_pairs.len(), deserialized.configs.len());
    assert!(matches!(deserialized.configs[0].contents, HttpSigConfigContents::Dh(_)));
    assert!(matches!(deserialized.configs[1].contents, HttpSigConfigContents::Dh(_)));
    assert!(matches!(deserialized.configs[2].contents, HttpSigConfigContents::Pk(_)));
    assert!(matches!(deserialized.configs[3].contents, HttpSigConfigContents::Pk(_)));
  }

  #[test]
  fn test_generate_null_configs() {
    let key_types = vec![];
    let keys = HttpSigPublicKeys::new(&key_types).unwrap();
    assert_eq!(keys.key_pairs.len(), 0);
    assert_eq!(keys.serialized_configs.len(), 2);
  }

  #[test]
  fn test_extract_pk_sk_from_pk_keypair() {
    let key_types = vec![HttpSigKeyTypes::Ed25519, HttpSigKeyTypes::Es256];

    let keys = HttpSigPublicKeys::new(&key_types).unwrap();

    // when sign
    let pk_sk = keys
      .key_pairs
      .iter()
      .map(|k| match k {
        HttpSigKeyPair::Dh(_) => panic!("Unexpected key type"),
        HttpSigKeyPair::Pk(kp) => (kp.public_key.clone(), kp.private_key.clone()),
      })
      .collect::<Vec<_>>();
    assert_eq!(pk_sk.len(), 2);

    // when retrieve public key to verify
    let deserialized = HttpSigConfigs::deserialize(&mut Bytes::from(keys.serialized_configs.clone())).unwrap();
    let pk = deserialized
      .configs
      .iter()
      .map(|c| match &c.contents {
        HttpSigConfigContents::Dh(_) => panic!("Unexpected key type"),
        HttpSigConfigContents::Pk(c) => c.public_key.clone(),
      })
      .collect::<Vec<_>>();
    assert_eq!(pk.len(), 2);
  }

  #[test]
  fn test_extract_pk_sk_and_derive_mac_from_dh_keypair() {
    let key_types = vec![HttpSigKeyTypes::Hs256X25519HkdfSha256, HttpSigKeyTypes::Hs256P256HkdfSha256];
    let alice_keys = HttpSigPublicKeys::new(&key_types).unwrap();
    let bob_keys = HttpSigPublicKeys::new(&key_types).unwrap();

    // key pairs at alice and bob
    let alice_kp = alice_keys
      .key_pairs
      .iter()
      .map(|k| match k {
        HttpSigKeyPair::Dh(kp) => kp,
        HttpSigKeyPair::Pk(_) => panic!("Unexpected key type"),
      })
      .collect::<Vec<_>>();
    let bob_kp = bob_keys
      .key_pairs
      .iter()
      .map(|k| match k {
        HttpSigKeyPair::Dh(kp) => kp,
        HttpSigKeyPair::Pk(_) => panic!("Unexpected key type"),
      })
      .collect::<Vec<_>>();

    // deserialize alice pk at bob side
    let binding = HttpSigConfigs::deserialize(&mut Bytes::from(alice_keys.serialized_configs.clone())).unwrap();
    let alice_pk_deserialized = binding
      .configs
      .iter()
      .map(|c| match &c.contents {
        HttpSigConfigContents::Dh(c) => c,
        HttpSigConfigContents::Pk(_) => panic!("Unexpected key type"),
      })
      .collect::<Vec<_>>();

    // deserialize bob pk at alice side
    let binding = HttpSigConfigs::deserialize(&mut Bytes::from(bob_keys.serialized_configs.clone())).unwrap();
    let bob_pk_deserialized = binding
      .configs
      .iter()
      .map(|c| match &c.contents {
        HttpSigConfigContents::Dh(c) => c,
        HttpSigConfigContents::Pk(_) => panic!("Unexpected key type"),
      })
      .collect::<Vec<_>>();

    // derive master secret key at both sides
    let alice_secrets = alice_kp
      .iter()
      .zip(bob_pk_deserialized.iter())
      .map(|(kp, pk)| kp.derive_secret(pk))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();

    let bob_secrets = bob_kp
      .iter()
      .zip(alice_pk_deserialized.iter())
      .map(|(kp, pk)| kp.derive_secret(pk))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();

    assert!(alice_secrets.iter().zip(bob_secrets.iter()).all(|(a, b)| a == b));

    // derive session key and random nonce at alice side
    let alice_session_key_nonce = alice_secrets
      .iter()
      .map(|s| s.derive_session_key_with_random_nonce(&mut rand::thread_rng()))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    let nonces = alice_session_key_nonce.iter().map(|s| s.nonce().to_vec()).collect::<Vec<_>>();

    // derive session key and given nonce at bob side
    let bob_session_key_nonce = bob_secrets
      .iter()
      .zip(nonces.iter())
      .map(|(s, n)| s.derive_session_key_with_nonce(n))
      .collect::<Result<Vec<_>, _>>()
      .unwrap();

    // check if session key and nonce are same at both sides
    assert!(alice_session_key_nonce
      .iter()
      .zip(bob_session_key_nonce.iter())
      .all(|(a, b)| a == b));
  }
}
