use super::{dns, target_main::build_http_response, InnerTarget};
use crate::{
  constants::{
    DNS_QUERY_PARAM, DOH_CONTENT_TYPE, MAX_DNS_QUESTION_LEN, MAX_DNS_RESPONSE_LEN, MIN_DNS_PACKET_LEN,
    ODOH_CONTENT_TYPE, TARGET_UDP_TCP_RATIO,
  },
  error::*,
  hyper_body::BoxBody,
  message_util::{check_content_type, inspect_host, read_request_body, RequestType},
  trace::*,
};
use base64::{engine::general_purpose, Engine as _};
use byteorder::{BigEndian, ByteOrder};
use futures::TryFutureExt;
use http::{Method, Request, Response};
use hyper::body::Body;
use std::net::SocketAddr;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpSocket, UdpSocket},
  time::timeout,
};
use tracing::{instrument, Instrument as _};

#[derive(Debug)]
/// Dns response object
struct DnsResponse {
  /// Raw Dns response packet
  packet: Vec<u8>,
  /// TTL
  ttl: u32,
}

impl InnerTarget {
  #[instrument(name = "target_serve", skip_all)]
  /// Serve request as a DoH or (M)ODoH target
  /// 1. check host, method and listening path: as described in [RFC9230](https://datatracker.ietf.org/doc/rfc9230/) and Golang implementation [odoh-server-go](https://github.com/cloudflare/odoh-server-go), only post method is allowed for ODoH. But Get method must be implemented for standard DoH.
  /// 2. check content type: "application/oblivious-dns-message" for MODoH and "application/dns-message" for DoH are allowed.
  /// 3. retrieve query and check if it is a valid doh/odoh query
  /// 4. forward request to upstream resolver and receive a response.
  /// 5. build response and return it to client
  pub async fn serve<B>(&self, req: Request<B>) -> HttpResult<Response<BoxBody>>
  where
    B: Body + Unpin,
  {
    // check host
    inspect_host(&req, &self.target_host)?;
    // check path
    if req.uri().path() != self.target_path {
      return Err(HttpError::InvalidPath);
    };
    // check method
    match *req.method() {
      Method::POST => {
        // check request type
        match check_content_type(&req)? {
          RequestType::DoH => {
            debug!("Serve DoH query (Post) as a target server");

            #[cfg(feature = "metrics")]
            self.meters.query_target_doh_post.add(1_u64, &[]);

            let mut query = read_request_body(&mut req.into_body()).await?;
            let res = timeout(self.timeout, self.resolve(&mut query))
              .await
              .map_err(|_| HttpError::UpstreamTimeout)??;
            let resp = build_http_response(&res.packet, res.ttl as u64, DOH_CONTENT_TYPE, true)?;
            Ok(resp)
          }
          RequestType::ODoH => {
            debug!("Serve (M)ODoH query as a target server");

            #[cfg(feature = "metrics")]
            self.meters.query_target_modoh.add(1_u64, &[]);

            let encrypted_query = read_request_body(&mut req.into_body()).await?;
            let lock = self.odoh_configs.read().await;
            let public_key = lock.clone();
            drop(lock);
            let (mut query, context) = public_key.decrypt_query(encrypted_query)?;
            let res = timeout(self.timeout, self.resolve(&mut query))
              .await
              .map_err(|_| HttpError::UpstreamTimeout)??;
            let encrypted_body = context.encrypt_response(res.packet)?;
            let resp = build_http_response(&encrypted_body, 0u64, ODOH_CONTENT_TYPE, false)?;
            Ok(resp)
          }
        }
      }
      Method::GET => {
        // check request type, only doh is allowed
        match check_content_type(&req)? {
          RequestType::DoH => {
            debug!("Serve (M)ODoH query (Get) as a target server");

            #[cfg(feature = "metrics")]
            self.meters.query_target_doh_get.add(1_u64, &[]);

            let mut query = query_from_query_string(req)?;
            let res = timeout(self.timeout, self.resolve(&mut query))
              .await
              .map_err(|_| HttpError::UpstreamTimeout)??;
            let resp = build_http_response(&res.packet, res.ttl as u64, DOH_CONTENT_TYPE, true)?;
            Ok(resp)
          }
          _ => Err(HttpError::InvalidMethod),
        }
      }
      _ => Err(HttpError::InvalidMethod),
    }
  }

  #[instrument(level = "debug", name = "target_resolve", skip_all)]
  /// Resolve raw dns query by the upstream resolver
  async fn resolve(&self, query: &mut Vec<u8>) -> HttpResult<DnsResponse> {
    if query.len() < MIN_DNS_PACKET_LEN {
      return Err(HttpError::IncompleteQuery);
    }
    dns::set_edns_max_payload_size(query, MAX_DNS_RESPONSE_LEN as _).map_err(|_| HttpError::InvalidDnsQuery)?;

    // focus on the response from the upstream dns server to count metrics
    let resp = self.resolve_inner(query).await;

    #[cfg(feature = "metrics")]
    if resp.is_err() {
      let kind = resp.as_ref().unwrap_err().to_string();
      self
        .meters
        .upstream_raw_dns_server_error
        .add(1_u64, &[opentelemetry::KeyValue::new("kind", kind)]);
    }

    #[allow(clippy::let_and_return)]
    resp
  }

  #[instrument(level = "debug", name = "target_resolve_inner", skip_all)]
  /// Resolve raw dns query by the upstream resolver (inner to count metrics)
  async fn resolve_inner(&self, query: &mut Vec<u8>) -> HttpResult<DnsResponse> {
    let (min_ttl, max_ttl, err_ttl) = (&self.min_ttl, &self.max_ttl, &self.err_ttl);

    let mut packet = vec![0; MAX_DNS_RESPONSE_LEN];

    // UDP
    {
      let socket = UdpSocket::bind(&self.local_bind_address)
        .await
        .map_err(|_| HttpError::UdpSocketError)?;
      let expected_server_address = &self.upstream;
      socket
        .send_to(query, self.upstream)
        .map_err(|_| HttpError::UdpSocketError)
        .instrument(tracing::debug_span!("send_resolve_udp"))
        .await?;
      let (len, response_server_address) = socket
        .recv_from(&mut packet)
        .map_err(|_| HttpError::UdpSocketError)
        .instrument(tracing::debug_span!("recv_resolve_udp"))
        .await?;
      if len < MIN_DNS_PACKET_LEN || *expected_server_address != response_server_address {
        return Err(HttpError::UpstreamIssue);
      }
      packet.truncate(len);
    }

    // TCP
    if dns::is_truncated(&packet) {
      let clients_count = &self.request_count.current();
      if self.max_tcp_sessions >= TARGET_UDP_TCP_RATIO
        && *clients_count >= self.max_tcp_sessions as isize / TARGET_UDP_TCP_RATIO as isize
      {
        return Err(HttpError::TooManyTcpSessions);
      }
      let socket = match self.upstream {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
      }
      .map_err(|_| HttpError::TcpSocketError)?;

      let mut ext_socket = socket
        .connect(self.upstream)
        .await
        .map_err(|_| HttpError::TcpSocketError)?;
      ext_socket.set_nodelay(true).map_err(|_| HttpError::TcpSocketError)?;
      let mut binlen = [0u8, 0];
      BigEndian::write_u16(&mut binlen, query.len() as u16);
      ext_socket
        .write_all(&binlen)
        .instrument(tracing::debug_span!("send_query_len_tcp"))
        .await
        .map_err(|_| HttpError::TcpSocketError)?;
      ext_socket
        .write_all(query)
        .instrument(tracing::debug_span!("send_resolve_tcp"))
        .await
        .map_err(|_| HttpError::TcpSocketError)?;
      ext_socket.flush().await.map_err(|_| HttpError::TcpSocketError)?;
      ext_socket
        .read_exact(&mut binlen)
        .instrument(tracing::debug_span!("recv_response_len_tcp"))
        .await
        .map_err(|_| HttpError::TcpSocketError)?;
      let packet_len = BigEndian::read_u16(&binlen) as usize;
      if !(MIN_DNS_PACKET_LEN..=MAX_DNS_RESPONSE_LEN).contains(&packet_len) {
        return Err(HttpError::UpstreamIssue);
      }
      packet = vec![0u8; packet_len];
      ext_socket
        .read_exact(&mut packet)
        .instrument(tracing::debug_span!("recv_resolve_tcp"))
        .await
        .map_err(|_| HttpError::TcpSocketError)?;

      #[cfg(feature = "metrics")]
      self.meters.upstream_query_tcp.add(1_u64, &[]);
    }

    let ttl = if dns::is_recoverable_error(&packet) {
      *err_ttl
    } else {
      match dns::min_ttl(&packet, *min_ttl, *max_ttl, *err_ttl) {
        Err(_) => return Err(HttpError::UpstreamIssue),
        Ok(ttl) => ttl,
      }
    };
    dns::add_edns_padding(&mut packet)
      .map_err(|_| HttpError::TooLargeDnsResponse)
      .ok();
    Ok(DnsResponse { packet, ttl })
  }
}

#[instrument(level = "debug", skip_all)]
/// Build DNS query binary from query string in DoH case
fn query_from_query_string<B>(req: Request<B>) -> HttpResult<Vec<u8>> {
  let http_query = req.uri().query().unwrap_or("");
  let question_str = http_query
    .split('&')
    .filter(|v| v.split('=').next() == Some(DNS_QUERY_PARAM))
    .map(|v| v.split('=').nth(1))
    .next()
    .and_then(|v| v)
    .ok_or_else(|| HttpError::InvalidDnsQuery)?;

  if question_str.len() > MAX_DNS_QUESTION_LEN * 4 / 3 {
    return Err(HttpError::InvalidDnsQuery);
  }

  let query = general_purpose::URL_SAFE_NO_PAD
    .decode(question_str)
    .map_err(|_| HttpError::InvalidDnsQuery)?;
  Ok(query)
}
