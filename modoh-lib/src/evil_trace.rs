use crate::constants::EVIL_TRACE_HEADER_NAME;
use anyhow::anyhow;
use http::Request;
use hyper::header::HeaderName;
use opentelemetry::trace::{SpanContext, SpanId, TraceFlags, TraceId};

#[allow(unused)]
/// Trace context
pub(crate) struct TraceCX {
  pub(crate) version: String, // 00
  pub(crate) trace_id: String,
  pub(crate) span_id: String,
  pub(crate) trace_flags: String,
}

impl TryFrom<String> for TraceCX {
  type Error = anyhow::Error;

  fn try_from(value: String) -> Result<Self, Self::Error> {
    let mut iter = value.split('-');
    let version = iter.next().ok_or_else(|| anyhow!("Invalid trace context"))?;
    let trace_id = iter.next().ok_or_else(|| anyhow!("Invalid trace context"))?;
    let span_id = iter.next().ok_or_else(|| anyhow!("Invalid trace context"))?;
    let trace_flags = iter.next().ok_or_else(|| anyhow!("Invalid trace context"))?;
    Ok(TraceCX {
      version: version.to_string(),
      trace_id: trace_id.to_string(),
      span_id: span_id.to_string(),
      trace_flags: trace_flags.to_string(),
    })
  }
}

impl From<TraceCX> for SpanContext {
  fn from(val: TraceCX) -> Self {
    let trace_flags = match val.trace_flags.as_str() {
      "00" => TraceFlags::NOT_SAMPLED,
      "01" => TraceFlags::SAMPLED,
      _ => TraceFlags::default(),
    };
    SpanContext::new(
      TraceId::from_hex(&val.trace_id).unwrap(),
      SpanId::from_hex(&val.span_id).unwrap(),
      trace_flags,
      false,
      opentelemetry::trace::TraceState::default(),
    )
  }
}

/// Get span context built from trace header from http request
/// Definition of http header for trace
/// https://uptrace.dev/opentelemetry/opentelemetry-traceparent.html
/// ```test:
/// # {version}-{trace_id}-{span_id}-{trace_flags}
/// traceparent: 00-80e1afed08e019fc1110464cfa66635c-7a085853722dc6d2-01
/// ```
pub(crate) fn get_span_cx_from_request<B>(req: &Request<B>) -> Option<SpanContext> {
  let header_name = HeaderName::from_static(EVIL_TRACE_HEADER_NAME);
  let header_value = req.headers().get(&header_name)?;
  let header_value = header_value.to_str().ok()?;
  TraceCX::try_from(header_value.to_string()).ok().map(SpanContext::from)
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::header::HeaderValue;
  use opentelemetry::trace::TraceState;

  #[test]
  fn test_get_trace_cx_from_request() {
    let req = Request::builder()
      .header(
        HeaderName::from_static(EVIL_TRACE_HEADER_NAME),
        HeaderValue::from_static("00-80e1afed08e019fc1110464cfa66635c-7a085853722dc6d2-01"),
      )
      .body(http_body_util::Empty::<hyper::body::Bytes>::new())
      .unwrap();
    let span_context = get_span_cx_from_request(&req).unwrap();
    assert_eq!(
      span_context,
      SpanContext::new(
        TraceId::from_hex("80e1afed08e019fc1110464cfa66635c").unwrap(),
        SpanId::from_hex("7a085853722dc6d2").unwrap(),
        TraceFlags::SAMPLED,
        false,
        TraceState::default(),
      )
    );
  }
}
