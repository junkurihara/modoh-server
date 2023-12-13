use crate::{error::*, log::*, AccessConfig};
use http::{header, HeaderMap};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

// /// Header keys that may contain the client IP address by previous routers like CDNs.
// const HEADER_IP_KEYS: &[&str] = &[
//   "x-client-ip",
//   "x-forwarded-for",
//   "x-real-ip",
//   // load balancer like pulse secure
//   "x-cluster-client-ip",
//   // cloudflare v4
//   "cf-connecting-ip",
//   // cloudflare v6
//   "cf-connecting-ipv6",
//   // cloudflare enterprise
//   "true-client-ip",
//   // fastly
//   "fastly-client-ip",
// ];

// FastlyやCloudflareの場合、remote_addrがそれらCDNのアドレス帯に含まれているかチェックする。
// remote_addrはTCP/QUIC handshakeが終わっているとして、xffとかはいくらでも偽装できるので一旦必ずCDNのIPチェックしないとダメ。CDN含め信頼できるIPを全部弾いた上で、一番過去のやつがsourceとみなすしかない。
// 単純に一番過去のやつではない
// https://www.m3tech.blog/entry/x-forwarded-for
// https://christina04.hatenablog.com/entry/2016/10/25/190000
// https://mrk21.hatenablog.com/entry/2020/08/06/214922
// https://developers.cloudflare.com/fundamentals/reference/http-request-headers/
// https://developer.fastly.com/reference/http/http-headers/Fastly-Client-IP/
// Forwarded header
// https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
// https://datatracker.ietf.org/doc/html/rfc7239

// cloudflare: https://developers.cloudflare.com/api/operations/cloudflare-i-ps-cloudflare-ip-details
// fastly: https://developer.fastly.com/reference/api/utils/public-ip-list/
// https://github.com/femueller/cloud-ip-ranges githubのリストを使う手もある

/// IpFilter filtering inbound request.
pub(crate) struct IpFilter {
  /// allowed source ip addresses
  allowed_source_ip_addresses: Vec<IpNet>,
  /// trusted cdn ip addresses
  trusted_cdn_ip_addresses: Vec<IpNet>,
  /// whether to trust previous hop reverse proxy
  trust_previous_hop: bool,
}

impl IpFilter {
  /// Create new IpFilter
  pub(crate) fn new(access_config: &AccessConfig) -> Self {
    let allowed_source_ip_addresses = access_config.allowed_source_ip_addresses.clone();
    let trusted_cdn_ip_addresses = access_config.trusted_cdn_ip_addresses.clone();
    Self {
      allowed_source_ip_addresses,
      trusted_cdn_ip_addresses,
      trust_previous_hop: access_config.trust_previous_hop,
    }
  }

  /// Check if the incoming request is allowed to be forwarded by source ip filter
  /// Note that `peer-addr` is always the address of the reverse proxy.
  pub(crate) fn is_allowed_request(&self, peer_addr: &IpAddr, req_header: &HeaderMap) -> HttpResult<()> {
    // Check if the source ip address is allowed if trust_previous_hop is false
    if !self.trust_previous_hop && !self.is_allowed(peer_addr) {
      return Err(HttpError::ForbiddenSourceAddress(format!(
        "Previous hop ip address {} is not allowed",
        peer_addr
      )));
    }

    // First check the Forwarded header, and if exists (or invalid), capture this flow to assess the source ip address (skip x-forwarded-for, etc.)
    let forwarded = retrieve_for_from_forwarded(req_header)?;
    if !forwarded.is_empty() {
      debug!("Forwarded header found: {:?}", forwarded);
      return self.is_origin_allowed(&forwarded);
    }

    // Second check the X-Forwarded-For header and if exists (or invalid), capture this flow
    let xff = retrieve_from_xff(req_header)?;
    if !xff.is_empty() {
      debug!("XFF header found: {:?}", xff);
      return self.is_origin_allowed(&xff);
    }

    // In this case, we can see the origin is simply the peer_addr, then Ok(())
    debug!("No XFF and Forwarded header found. Pass: {}", peer_addr);
    Ok(())
  }

  /// Remove proxy addresses from the given Ve<IpAddr>
  fn is_origin_allowed(&self, forwarded_addresses: &[IpAddr]) -> HttpResult<()> {
    let filtered_proxies = forwarded_addresses
      .iter()
      .filter(|x| !self.trusted_cdn_ip_addresses.iter().any(|y| y.contains(*x)))
      .collect::<Vec<_>>();
    debug!("Remained ips after pruning CDN ips: {:?}", filtered_proxies);

    let origin = if filtered_proxies.is_empty() {
      // If all proxies are trusted, then the origin is supposed to be the first value
      forwarded_addresses.first().unwrap()
    } else {
      // Otherwise, the first untrusted hop is the origin
      filtered_proxies.last().unwrap()
    };
    if self.is_allowed(origin) {
      return Ok(());
    }
    Err(HttpError::ForbiddenSourceAddress(format!(
      "Origin ip address {} is not allowed",
      origin
    )))
  }

  /// Check if the source ip address is allowed
  fn is_allowed(&self, source_ip: &IpAddr) -> bool {
    self.allowed_source_ip_addresses.iter().any(|x| x.contains(source_ip))
  }
}

/// Retrieved proxy addresses from X-Forwarded-For header
fn retrieve_from_xff(header: &HeaderMap) -> HttpResult<Vec<IpAddr>> {
  let xff = header::HeaderName::from_static("x-forwarded-for");
  let xff_view = header.get_all(xff).into_iter().collect::<Vec<_>>();
  if xff_view.is_empty() {
    return Ok(vec![]);
  }

  let entries = xff_view
    .iter()
    .flat_map(|v| v.to_str().unwrap_or_default().split(','))
    .map(|v| v.trim())
    .collect::<Vec<_>>();

  let entries_extracted_for = entries
    .iter()
    .filter_map(|entry| manipulate_ip_string(entry))
    .collect::<Vec<_>>();
  if entries.len() != entries_extracted_for.len() {
    return Err(HttpError::InvalidXForwardedForHeader(
      "X-Forwarded-For header does not contain valid ip address".to_string(),
    ));
  }
  Ok(entries_extracted_for)
}

/// Retrieved proxy addresses from Forwarded header
/// [RFC7239](https://www.rfc-editor.org/rfc/rfc7239)
fn retrieve_for_from_forwarded(header: &HeaderMap) -> HttpResult<Vec<IpAddr>> {
  let forwarded_view = header.get_all(header::FORWARDED).into_iter().collect::<Vec<_>>();
  if forwarded_view.is_empty() {
    return Ok(vec![]);
  }

  let entries = forwarded_view
    .iter()
    .flat_map(|v| v.to_str().unwrap_or_default().split(','))
    .map(|s| s.to_ascii_lowercase())
    .collect::<Vec<_>>();

  if !entries.iter().all(|entry| entry.contains("for=")) {
    return Err(HttpError::InvalidForwardedHeader(
      "Forwarded header does not contain 'for='".to_string(),
    ));
  }
  let entries_extracted_for = entries
    .iter()
    .filter_map(|entry| entry.split(';').find(|x| x.trim().starts_with("for=")))
    .map(|v| v.split('=').last().unwrap_or_default().trim().trim_matches('"'))
    .filter_map(manipulate_ip_string)
    .collect::<Vec<_>>();
  if entries.len() != entries_extracted_for.len() {
    return Err(HttpError::InvalidForwardedHeader(
      "Forwarded header does not contain valid 'for='".to_string(),
    ));
  }
  Ok(entries_extracted_for)
}

fn manipulate_ip_string(ip: &str) -> Option<IpAddr> {
  if ip.starts_with('[') && ip.contains(']') {
    // ipv6 case with bracket
    // ip[1..ip.len() - 1].to_string()
    return ip[1..].split(']').next().unwrap_or_default().parse::<IpAddr>().ok();
  }
  // ipv4 case, or ipv6 case without bracket, i.e., without port
  if !ip.contains(':') {
    // ipv4 case without port
    return ip.parse::<IpAddr>().ok();
  }
  if ip.chars().filter(|v| v == &':').count() == 1 {
    // ipv4 case with port
    return ip.parse::<SocketAddr>().map(|v| v.ip()).ok();
  }
  // ipv6 case without bracket
  ip.parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_forwarded_header() {
    let mut req_header = HeaderMap::new();
    req_header.insert(
      header::FORWARDED,
      header::HeaderValue::from_str("proto=https;for=1.0.0.0;by=1.1.1.1").unwrap(),
    );
    req_header.append(
      header::FORWARDED,
      header::HeaderValue::from_str("proto=https;for=2.0.0.0;by=1.1.1.1").unwrap(),
    );
    req_header.append(
      header::FORWARDED,
      header::HeaderValue::from_str("proto=https;for=3.0.0.0;by=1.1.1.1, for=4.0.0.0:1234").unwrap(),
    );

    let retrieved = retrieve_for_from_forwarded(&req_header).unwrap();
    assert_eq!(retrieved.len(), 4);
    let mut iter = retrieved.iter();
    assert_eq!(iter.next(), Some(&IpAddr::from([1, 0, 0, 0])));
    assert_eq!(iter.next(), Some(&IpAddr::from([2, 0, 0, 0])));
    assert_eq!(iter.next(), Some(&IpAddr::from([3, 0, 0, 0])));
    assert_eq!(iter.next(), Some(&IpAddr::from([4, 0, 0, 0])));
    assert_eq!(iter.next(), None);

    let mut req_header = HeaderMap::new();
    req_header.insert(
      header::FORWARDED,
      header::HeaderValue::from_str("proto=https;For=\"[2001:db8:cafe::17]\"").unwrap(),
    );
    req_header.append(
      header::FORWARDED,
      header::HeaderValue::from_str("proto=https;For=\"[2001:db8:cafe::18]:1234\"").unwrap(),
    );
    let retrieved = retrieve_for_from_forwarded(&req_header).unwrap();
    assert_eq!(retrieved.len(), 2);
    let mut iter = retrieved.iter();
    assert_eq!(
      iter.next(),
      Some(&IpAddr::from([0x2001, 0xdb8, 0xcafe, 0, 0, 0, 0, 0x17]))
    );
    assert_eq!(
      iter.next(),
      Some(&IpAddr::from([0x2001, 0xdb8, 0xcafe, 0, 0, 0, 0, 0x18]))
    );
    assert_eq!(iter.next(), None);
  }
  #[test]
  fn test_xff_header() {
    let xff = header::HeaderName::from_static("x-forwarded-for");
    let mut req_header = HeaderMap::new();
    req_header.insert(
      xff.clone(),
      header::HeaderValue::from_str("1.0.0.0, 2.0.0.0, 3.0.0.0").unwrap(),
    );
    req_header.append(xff, header::HeaderValue::from_str("4.0.0.0").unwrap());

    let retrieved = retrieve_from_xff(&req_header).unwrap();
    assert_eq!(retrieved.len(), 4);
    let mut iter = retrieved.iter();
    assert_eq!(iter.next(), Some(&IpAddr::from([1, 0, 0, 0])));
    assert_eq!(iter.next(), Some(&IpAddr::from([2, 0, 0, 0])));
    assert_eq!(iter.next(), Some(&IpAddr::from([3, 0, 0, 0])));
    assert_eq!(iter.next(), Some(&IpAddr::from([4, 0, 0, 0])));
    assert_eq!(iter.next(), None);
  }
}
