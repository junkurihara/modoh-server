pub use anyhow::{anyhow, bail, ensure, Context};
use hyper::StatusCode;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, RelayError>;
pub type HttpResult<T> = std::result::Result<T, HttpError>;

/// Describes things that can go wrong in the relay
#[derive(Debug, Error)]
pub enum RelayError {
  #[error("Failed to bind TCP socket")]
  BindTcpSocketError(#[from] std::io::Error),
  #[error("No Validator")]
  NoValidator,
  #[error("Failed to build forwarder")]
  BuildForwarderError,
  #[error("Failed to build validator")]
  BuildValidatorError,
  #[error(transparent)]
  Other(#[from] anyhow::Error),
}

/// Describes things that can go wrong in the forwarder
#[derive(Debug, Error)]
pub enum HttpError {
  #[error("Invalid host")]
  InvalidHost,
  #[error("Invalid method")]
  InvalidMethod,
  #[error("Invalid path")]
  InvalidPath,
  #[error("Invalid url")]
  InvalidUrl,
  #[error("Invalid url query parameter")]
  InvalidQueryParameter,
  #[error("Loop detected")]
  LoopDetected,
  #[error("Too many subsequent nodes")]
  TooManySubsequentNodes,

  #[error("Invalid content type")]
  InvalidContentTypeString,
  #[error("Not odoh content type")]
  NotObliviousDnsMessageContentType,
  #[error("Invalid accept string")]
  InvalidAcceptString,
  #[error("Not odoh accept")]
  NotObliviousDnsMessageAccept,
  #[error("No content type and accept")]
  NoContentTypeAndAccept,

  #[error("No body in request")]
  NoBodyInRequest,
  #[error("Too large body")]
  TooLargeRequestBody,

  #[error("Failed to send request")]
  SendRequestError(#[from] hyper::Error),
  #[error("Invalid response content type")]
  InvalidResponseContentType,
  #[error("Invalid response body")]
  InvalidResponseBody,

  #[error("No authorization header")]
  NoAuthorizationHeader,
  #[error("Invalid authorization header")]
  InvalidAuthorizationHeader,
  #[error("Invalid token")]
  InvalidToken,

  #[error(transparent)]
  Other(#[from] anyhow::Error),
}

impl From<HttpError> for StatusCode {
  fn from(e: HttpError) -> StatusCode {
    match e {
      HttpError::InvalidHost => StatusCode::MISDIRECTED_REQUEST,
      HttpError::InvalidMethod => StatusCode::METHOD_NOT_ALLOWED,
      HttpError::InvalidPath => StatusCode::NOT_FOUND,
      HttpError::InvalidUrl => StatusCode::BAD_REQUEST,
      HttpError::InvalidQueryParameter => StatusCode::BAD_REQUEST,
      HttpError::LoopDetected => StatusCode::LOOP_DETECTED,
      HttpError::TooManySubsequentNodes => StatusCode::BAD_REQUEST,
      HttpError::InvalidContentTypeString => StatusCode::BAD_REQUEST,
      HttpError::NotObliviousDnsMessageContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
      HttpError::InvalidAcceptString => StatusCode::BAD_REQUEST,
      HttpError::NotObliviousDnsMessageAccept => StatusCode::NOT_ACCEPTABLE,
      HttpError::NoContentTypeAndAccept => StatusCode::UNSUPPORTED_MEDIA_TYPE,
      HttpError::NoBodyInRequest => StatusCode::BAD_REQUEST,
      HttpError::SendRequestError(_) => StatusCode::BAD_GATEWAY,
      HttpError::InvalidResponseContentType => StatusCode::BAD_GATEWAY,
      HttpError::InvalidResponseBody => StatusCode::BAD_GATEWAY,

      HttpError::NoAuthorizationHeader => StatusCode::FORBIDDEN,
      HttpError::InvalidAuthorizationHeader => StatusCode::FORBIDDEN,
      HttpError::InvalidToken => StatusCode::UNAUTHORIZED,

      HttpError::TooLargeRequestBody => StatusCode::PAYLOAD_TOO_LARGE,
      _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
  }
}
