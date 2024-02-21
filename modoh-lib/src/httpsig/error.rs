use thiserror::Error;

/// Describes things that can go wrong in the Dh for HttpSig HMAC verification
#[derive(Debug, Error)]
pub enum HttpSigDhError {
  /// The input is too short
  #[error("Input too short")]
  ShortInput,
  /// The input length is invalid
  #[error("Invalid input length")]
  InvalidInputLength,
  /// The input is invalid
  #[error("Invalid parameter")]
  InvalidParameter,

  #[error(transparent)]
  Other(#[from] anyhow::Error),
}
