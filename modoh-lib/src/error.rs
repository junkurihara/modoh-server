pub use anyhow::{anyhow, bail, ensure, Context};
use http::StatusCode;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, MODoHError>;
pub type HttpResult<T> = std::result::Result<T, HttpError>;

/// Describes things that can go wrong in the relay
#[derive(Debug, Error)]
pub enum MODoHError {
  #[error("Failed to bind TCP socket")]
  BindTcpSocketError(#[from] std::io::Error),
  #[error("Failed to build HTTP client")]
  FailedToBuildHttpClient(String),
  #[error("No validator")]
  NoValidator,
  #[error("Failed to build validator")]
  BuildValidatorError,
  #[error("Failed to build relay")]
  BuildRelayError,
  #[error("Failed to build target")]
  BuildTargetError,
  #[error("Failed to build odoh config")]
  ODoHConfigError(#[from] odoh_rs::Error),
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

  #[error("Unsupported request type")]
  UnsupportedRequestType,
  #[error("Invalid content type")]
  InvalidContentTypeString,
  #[error("Invalid accept string")]
  InvalidAcceptString,
  #[error("No content type and accept")]
  NoContentTypeAndAccept,

  #[error("No body in request")]
  NoBodyInRequest,
  #[error("Too large body")]
  TooLargeRequestBody,

  #[error("Failed to send request")]
  SendRequestError(#[from] hyper_util::client::legacy::Error),
  #[error("Invalid response content type")]
  InvalidResponseContentType,
  #[error("Invalid response body")]
  InvalidResponseBody,

  #[error("Invalid ODoH config")]
  InvalidODoHConfig,
  #[error("Invalid ODoH query")]
  InvalidODoHQuery,
  #[error("Stale ODoH key")]
  ODoHStaleKey,
  #[error("Invalid ODoH response")]
  InvalidODoHResponse,

  #[error("Invalid DNS query")]
  InvalidDnsQuery,
  #[error("Incomplete query")]
  IncompleteQuery,
  #[error("Target Udp socket error")]
  UdpSocketError,
  #[error("Target Tcp socket error")]
  TcpSocketError,
  #[error("Target upstream issue")]
  UpstreamIssue,
  #[error("Too many TCP sessions")]
  TooManyTcpSessions,
  #[error("Too large DNS response")]
  TooLargeDnsResponse,
  #[error("Upstream timeout")]
  UpstreamTimeout,

  #[error("No authorization header")]
  NoAuthorizationHeader,
  #[error("Invalid authorization header")]
  InvalidAuthorizationHeader,
  #[error("Invalid token")]
  InvalidToken,

  #[error("Invalid forwarded header: {0}")]
  InvalidForwardedHeader(String),
  #[error("Invalid X-Forwarded-For header: {0}")]
  InvalidXForwardedForHeader(String),
  #[error("Forbidden source ip address: {0}")]
  ForbiddenSourceAddress(String),
  #[error("Forbidden destination domain: {0}")]
  ForbiddenDomain(String),

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
      HttpError::UnsupportedRequestType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
      HttpError::InvalidAcceptString => StatusCode::BAD_REQUEST,
      HttpError::NoContentTypeAndAccept => StatusCode::UNSUPPORTED_MEDIA_TYPE,

      HttpError::NoBodyInRequest => StatusCode::BAD_REQUEST,
      HttpError::TooLargeRequestBody => StatusCode::PAYLOAD_TOO_LARGE,

      HttpError::SendRequestError(_) => StatusCode::BAD_GATEWAY,
      HttpError::InvalidResponseContentType => StatusCode::BAD_GATEWAY,
      HttpError::InvalidResponseBody => StatusCode::BAD_GATEWAY,

      HttpError::InvalidODoHConfig => StatusCode::BAD_GATEWAY,
      HttpError::InvalidODoHQuery => StatusCode::BAD_REQUEST,
      HttpError::ODoHStaleKey => StatusCode::UNAUTHORIZED,
      HttpError::InvalidODoHResponse => StatusCode::BAD_REQUEST,

      HttpError::InvalidDnsQuery => StatusCode::BAD_REQUEST,
      HttpError::IncompleteQuery => StatusCode::UNPROCESSABLE_ENTITY,
      HttpError::UdpSocketError => StatusCode::INTERNAL_SERVER_ERROR,
      HttpError::TcpSocketError => StatusCode::INTERNAL_SERVER_ERROR,
      HttpError::UpstreamIssue => StatusCode::BAD_GATEWAY,
      HttpError::TooManyTcpSessions => StatusCode::SERVICE_UNAVAILABLE,
      HttpError::TooLargeDnsResponse => StatusCode::PAYLOAD_TOO_LARGE,
      HttpError::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,

      HttpError::NoAuthorizationHeader => StatusCode::FORBIDDEN,
      HttpError::InvalidAuthorizationHeader => StatusCode::FORBIDDEN,
      HttpError::InvalidToken => StatusCode::UNAUTHORIZED,
      HttpError::ForbiddenSourceAddress(_) => StatusCode::FORBIDDEN,
      HttpError::ForbiddenDomain(_) => StatusCode::FORBIDDEN,

      HttpError::InvalidForwardedHeader(_) => StatusCode::BAD_REQUEST,

      _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
  }
}
