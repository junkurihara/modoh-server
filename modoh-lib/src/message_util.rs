use crate::{
  constants::{DOH_CONTENT_TYPE, MAX_DNS_QUESTION_LEN, ODOH_CONTENT_TYPE},
  error::*,
};
use futures::StreamExt;
use http_body_util::BodyStream;
use hyper::{
  body::{Body, Buf},
  header, Request,
};
use std::str::FromStr;

/// Get HOST header and/or host name in url line in http request
/// Returns Err if both are specified and inconsistent, if none of them is specified, or if the host name is different from the given hostname in args.
/// Note that port is dropped even if specified.
pub(crate) fn inspect_host<B>(req: &Request<B>, hostname: &str) -> HttpResult<()> {
  let drop_port = |v: &str| {
    v.split(':')
      .next()
      .ok_or_else(|| HttpError::InvalidHost)
      .map(|s| s.to_string())
  };

  let host_header = req.headers().get(header::HOST).map(|v| v.to_str().map(drop_port));
  let host_url = req.uri().host().map(drop_port);

  let h = match (host_header, host_url) {
    (Some(Ok(Ok(hh))), Some(Ok(hu))) => {
      if hh != hu {
        return Err(HttpError::InvalidHost);
      }
      hh
    }
    (Some(Ok(Ok(hh))), None) => hh,
    (None, Some(Ok(hu))) => hu,
    _ => return Err(HttpError::InvalidHost),
  };
  if h != hostname {
    return Err(HttpError::InvalidHost);
  }
  Ok(())
}

#[derive(PartialEq, Eq, Debug)]
/// request message type
pub enum RequestType {
  /// Standard DoH
  DoH,
  /// (Mutualized) Oblivious DoH
  ODoH,
}
impl FromStr for RequestType {
  type Err = HttpError;
  fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
    match s.to_ascii_lowercase().as_str() {
      ODOH_CONTENT_TYPE => Ok(RequestType::ODoH),
      DOH_CONTENT_TYPE => Ok(RequestType::DoH),
      _ => Err(HttpError::UnsupportedRequestType),
    }
  }
}

/// parse and check content type and accept headers if both or either of them are "application/oblivious-dns-message" or "application/dns-message".
pub fn check_content_type<B>(req: &Request<B>) -> HttpResult<RequestType> {
  // get content type
  if let Some(content_type) = req.headers().get(header::CONTENT_TYPE) {
    let Ok(ct) = content_type.to_str() else {
      return Err(HttpError::InvalidContentTypeString);
    };
    let rt = RequestType::from_str(ct)?;
    return Ok(rt);
  }

  // check accept
  if let Some(accept) = req.headers().get(header::ACCEPT) {
    let Ok(ac) = accept.to_str() else {
      return Err(HttpError::InvalidAcceptString);
    };
    let mut ac_split = ac.split(',').map(|s| s.trim());
    let rt = ac_split
      .find_map(|s| RequestType::from_str(s).ok())
      .ok_or_else(|| HttpError::UnsupportedRequestType)?;
    return Ok(rt);
  };

  // neither content type nor accept is "application/oblivious-dns-message"/"application/dns-message"
  Err(HttpError::NoContentTypeAndAccept)
}

/// Read encrypted query from request body
pub async fn inspect_request_body<B: Body>(body: &B) -> HttpResult<()> {
  let max = body.size_hint().upper().unwrap_or(u64::MAX);
  if max > MAX_DNS_QUESTION_LEN as u64 {
    return Err(HttpError::TooLargeRequestBody);
  }
  if max == 0 {
    return Err(HttpError::NoBodyInRequest);
  }

  Ok(())
}

/// read request body into a vector
pub async fn read_request_body<B>(body: &mut B) -> HttpResult<Vec<u8>>
where
  B: Body + Unpin,
{
  inspect_request_body(body).await?;

  let mut sum_size = 0;
  let mut query = vec![];
  let mut stream = BodyStream::new(body);
  while let Some(chunk) = stream.next().await {
    let chunk = chunk
      .map_err(|_| HttpError::TooLargeRequestBody)?
      .into_data()
      .map(|v| v.chunk().to_vec())
      .map_err(|_| HttpError::TooLargeRequestBody)?;

    sum_size += chunk.len();
    if sum_size >= MAX_DNS_QUESTION_LEN {
      return Err(HttpError::TooLargeRequestBody);
    }
    query.extend(chunk);
  }

  Ok(query)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::str::FromStr;

  #[test]
  fn request_type_from_string() {
    assert_eq!(
      RequestType::from_str("application/oblivious-dns-message").unwrap(),
      RequestType::ODoH
    );
    assert_eq!(
      RequestType::from_str("application/dns-message").unwrap(),
      RequestType::DoH
    );
    assert!(RequestType::from_str("application/oblivious-dns-message1").is_err());
    assert!(RequestType::from_str("application/dns-message1").is_err());
    assert!(RequestType::from_str("application/oblivious-dns-message1").is_err());
    assert!(RequestType::from_str("application/dns-message1").is_err());
  }
}
