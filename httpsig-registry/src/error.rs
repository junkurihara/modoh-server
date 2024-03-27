use thiserror::Error;

/// Describes things that can go wrong in registry handling
#[derive(Debug, Error)]
pub enum ModohRegistryError {
  /// Url parse error
  #[error("Url parse error")]
  FailToParseUrl,
  /// IO error
  #[error("IO error")]
  Io(#[from] std::io::Error),
  /// Reqwest error
  #[error("Reqwest error")]
  Reqwest(#[from] reqwest::Error),
  /// Minisign error
  #[error("Minisign error")]
  Minisign(#[from] minisign_verify::Error),
}
