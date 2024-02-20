mod error;
mod httpsig_configs;

#[derive(Clone, Default)]
/// Public key and KEM types used for Diffie-Hellman key exchange for httpsig's hmac-sha256 signature.
pub enum DhKemTypes {
  #[default]
  /// x25519-hkdf-sha256
  X25519HkdfSha256,
  /// p256-hkdf-sha256
  P256HkdfSha256,
}

impl TryFrom<&str> for DhKemTypes {
  type Error = anyhow::Error;

  fn try_from(s: &str) -> Result<Self, Self::Error> {
    match s {
      "x25519-hkdf-sha256" => Ok(DhKemTypes::X25519HkdfSha256),
      "p256-hkdf-sha256" => Ok(DhKemTypes::P256HkdfSha256),
      _ => Err(anyhow::anyhow!("Invalid DhKemTypes: {}", s)),
    }
  }
}
