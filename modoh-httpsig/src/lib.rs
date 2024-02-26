mod common;
mod dh;
mod error;
mod mac_kdf;
mod pk;

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
