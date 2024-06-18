pub use tracing::{debug, error, info, warn};

#[cfg(feature = "qrlog")]
use crate::{constants::QRLOG_CHANNEL_SIZE, dns};
#[cfg(feature = "qrlog")]
use base64::{engine::general_purpose, Engine as _};
#[cfg(feature = "qrlog")]
use crossbeam_channel::{Receiver, Sender};
#[cfg(feature = "qrlog")]
use hickory_proto::op::Message;
#[cfg(feature = "qrlog")]
use http::HeaderMap;
#[cfg(feature = "qrlog")]
use std::{net::SocketAddr, sync::Arc};
#[cfg(feature = "qrlog")]
use tokio::sync::Notify;

#[cfg(feature = "qrlog")]
#[derive(Debug)]
/// Logging base for query-response
pub(crate) struct QrLoggingBase {
  /// Peer address
  peer_addr: SocketAddr,
  /// Raw DNS message packet either query or response
  raw_packet: Vec<u8>,
  /// HTTP request headers for the query
  http_req_headers: HeaderMap,
}

#[cfg(feature = "qrlog")]
impl From<(SocketAddr, Vec<u8>, HeaderMap)> for QrLoggingBase {
  fn from((peer_addr, raw_packet, http_req_headers): (SocketAddr, Vec<u8>, HeaderMap)) -> Self {
    Self {
      peer_addr,
      raw_packet,
      http_req_headers,
    }
  }
}

#[cfg(feature = "qrlog")]
impl QrLoggingBase {
  /// Log the query-response through tracing
  pub fn log(&self) {
    use hickory_proto::serialize::binary::BinDecodable;

    use crate::constants::QRLOG_EVENT_NAME;

    let span = tracing::info_span!(crate::constants::QRLOG_EVENT_NAME);
    let _guard = span.enter();

    let http_req_headers = &self.http_req_headers;

    let authorization_header = http_req_headers
      .get("authorization")
      .map(|v| v.to_str().unwrap_or_default())
      .and_then(|v| {
        if v.starts_with("Bearer ") {
          Some(v.trim_start_matches("Bearer ").to_string())
        } else {
          None
        }
      });
    let sub_id = authorization_header.as_ref().map(|v| {
      // If the token is an anonymous token or no token is supplied, the sub_id is empty.
      let claims = v.split('.').nth(1).unwrap_or_default();
      let claims = general_purpose::URL_SAFE_NO_PAD.decode(claims).unwrap_or_default();
      let claims = String::from_utf8(claims).unwrap_or_default();
      let claims: serde_json::Value = serde_json::from_str(&claims).unwrap_or_default();
      claims.get("sub").and_then(|v| v.as_str()).unwrap_or_default().to_string()
    });
    let x_forwarded_for = http_req_headers
      .get("x-forwarded-for")
      .map(|v| v.to_str().unwrap_or_default())
      .unwrap_or_default();
    let forwarded = http_req_headers
      .get("forwarded")
      .map(|v| v.to_str().unwrap_or_default())
      .unwrap_or_default();
    let content_type = http_req_headers
      .get("content-type")
      .map(|v| v.to_str().unwrap_or_default())
      .unwrap_or_default();

    let qr = dns::qr(&self.raw_packet);
    let rcode = dns::rcode(&self.raw_packet);
    let (qname, qtype, qclass) = dns::qname_qtype_qclass(&self.raw_packet).unwrap_or_default();
    let peer_addr = &self.peer_addr.to_string();

    let text_message = if dns::qr(&self.raw_packet) == 0 {
      "DNS query"
    } else {
      "DNS response"
    };

    // parse raw message
    let Ok(raw_message) = Message::from_bytes(&self.raw_packet) else {
      tracing::event!(name: QRLOG_EVENT_NAME, tracing::Level::ERROR, qr, rcode, qname, qtype, qclass, peer_addr, sub_id, x_forwarded_for, forwarded, content_type, "{text_message}: Message::from_bytes failed");
      return;
    };
    let raw_message = RawMessage::from(raw_message).to_string();

    tracing::event!(name: QRLOG_EVENT_NAME, tracing::Level::INFO, rcode, qname, qtype, qclass, peer_addr, sub_id, x_forwarded_for, forwarded, content_type, raw_message, "{text_message}");
  }
}

#[cfg(feature = "qrlog")]
struct RawMessage {
  inner: hickory_proto::op::Message,
}
#[cfg(feature = "qrlog")]
impl From<hickory_proto::op::Message> for RawMessage {
  fn from(inner: hickory_proto::op::Message) -> Self {
    Self { inner }
  }
}
#[cfg(feature = "qrlog")]
impl std::fmt::Display for RawMessage {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.inner)
  }
}

#[cfg(feature = "qrlog")]
/// Logger for query-response
pub(crate) struct QrLogger {
  /// Receiver for message
  qrlog_rx: Receiver<QrLoggingBase>,
  /// Notify for termination for the logger service
  term_notify: Option<Arc<Notify>>,
}

#[cfg(feature = "qrlog")]
impl QrLogger {
  /// Create a new instance of QrLogger
  pub(crate) fn new(term_notify: Option<Arc<Notify>>) -> (Sender<QrLoggingBase>, Self) {
    let (qrlog_tx, qrlog_rx) = crossbeam_channel::bounded(QRLOG_CHANNEL_SIZE);
    (qrlog_tx, Self { qrlog_rx, term_notify })
  }

  /// Start the logger service
  pub(crate) async fn start(&mut self) {
    let Some(ref term_notify) = self.term_notify else {
      while let Ok(qr_log) = self.qrlog_rx.recv() {
        qr_log.log();
      }
      return;
    };

    loop {
      tokio::select! {
        _ = term_notify.notified() => {
          info!("QrLogger is terminated via term_notify");
          break;
        }
        Ok(qr_log) = async { self.qrlog_rx.recv() } => {
          qr_log.log();
        }
      }
    }
  }
}
