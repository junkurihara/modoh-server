use thiserror::Error;

/// Describes things that can go wrong in the Dh for HttpSig HMAC/Sig verification
#[derive(Debug, Error)]
pub enum HttpSigError {
  /// The input is too short
  #[error("Input too short")]
  ShortInput,
  /// The input length is invalid
  #[error("Invalid input length")]
  InvalidInputLength,
  /// The input is invalid
  #[error("Invalid parameter")]
  InvalidParameter,

  #[error("Error in ec crypto library")]
  EcError(#[from] elliptic_curve::Error),

  #[error("Error in ed25519 crypto library")]
  Ed25519Error(#[from] ed25519_compact::Error),

  #[error("Invalid length for hkdf: {0}")]
  InvalidHkdfLength(String),

  #[error("Error in httpsig crate: {0}")]
  HttpSigError(#[from] httpsig::prelude::HttpSigError),

  #[error(transparent)]
  Other(#[from] anyhow::Error),
}
