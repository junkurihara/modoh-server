pub use anyhow::{anyhow, bail, ensure, Context};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, RelayError>;

/// Describes things that can go wrong in the relay
#[derive(Debug, Error)]
pub enum RelayError {
  #[error("Failed to parse validation key")]
  ValidationKeyParseError(#[from] spki::der::Error),
  #[error("Validation key is malformed")]
  ValidationKeyMalformed(#[from] spki::Error),
  #[error("Unsupported validation key")]
  UnsupportedValidationKey,

  #[error(transparent)]
  Other(#[from] anyhow::Error),
}
