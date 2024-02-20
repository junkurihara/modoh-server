use thiserror::Error;

pub type HttpSigResult<T> = std::result::Result<T, HttpSigError>;

/// Describes things that can go wrong in the relay
#[derive(Debug, Error)]
pub enum HttpSigError {
  #[error(transparent)]
  Other(#[from] anyhow::Error),
}
