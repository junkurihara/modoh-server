use super::relay_main::InnerRelay;
use crate::{constants::HOSTNAME, error::*, log::*};
use hyper::body::Body;
use hyper_util::client::legacy::connect::Connect;
use rustc_hash::FxHashMap as HashMap;
use url::Url;

const ODOH_TARGETHOST: &str = "targethost";
const ODOH_TARGETPATH: &str = "targetpath";
const MODOH_RELAYHOST: &str = "relayhost";
const MODOH_RELAYPATH: &str = "relaypath";

/// Loop detection
fn is_looped(current_url: &Url) -> bool {
  let mut seen = vec![current_url.host_str().unwrap_or(HOSTNAME).to_ascii_lowercase()];
  let hostnames = current_url.query_pairs().filter_map(|(k, v)| {
    // filter "targethost" or "relayhost"
    if k.contains("host") {
      Some(v)
    } else {
      None
    }
  });
  for h in hostnames {
    let hostname = h.to_ascii_lowercase();
    if seen.contains(&hostname) {
      return true;
    }
    seen.push(hostname);
  }
  false
}

impl<C, B> InnerRelay<C, B>
where
  C: Send + Sync + Connect + Clone + 'static,
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
  /// build next-hop url with loop detection and max subsequent nodes check
  pub fn build_nexthop_url(&self, current_url: &Url) -> HttpResult<Url> {
    // check loop
    if is_looped(current_url) {
      return Err(HttpError::LoopDetected);
    }

    let query_pairs = current_url.query_pairs().collect::<HashMap<_, _>>();
    if query_pairs.len() < 2 || query_pairs.len() % 2 != 0 {
      return Err(HttpError::InvalidQueryParameter);
    }
    let subseq_node_num = query_pairs.len() / 2;
    if subseq_node_num > self.max_subseq_nodes {
      return Err(HttpError::TooManySubsequentNodes);
    }

    // assert that query pair contains targethost and targetpath
    let (Some(targethost), Some(targetpath)) = (query_pairs.get(ODOH_TARGETHOST), query_pairs.get(ODOH_TARGETPATH))
    else {
      return Err(HttpError::InvalidQueryParameter);
    };

    // in case of ODoH
    if query_pairs.len() == 2 {
      let mut next_hop_url = Url::parse(format!("https://{targethost}").as_str()).map_err(|e| {
        error!("{e}");
        HttpError::InvalidQueryParameter
      })?;
      next_hop_url.set_path(targetpath);
      return Ok(next_hop_url);
    }

    // in case of (M)ODoH
    // assert that query contains relayhost and relaypath
    let query_check = (1..(query_pairs.len() - 2) / 2 + 1).all(|idx| {
      let host_key = format!("{}[{}]", MODOH_RELAYHOST, idx);
      let path_key = format!("{}[{}]", MODOH_RELAYPATH, idx);
      query_pairs.contains_key(host_key.as_str()) && query_pairs.contains_key(path_key.as_str())
    });
    if !query_check {
      return Err(HttpError::InvalidQueryParameter);
    }

    // nexthop host and path
    let mut next_hop_url = Url::parse(
      format!(
        "https://{}",
        query_pairs.get(format!("{MODOH_RELAYHOST}[1]").as_str()).unwrap()
      )
      .as_str(),
    )
    .map_err(|e| {
      error!("{e}");
      HttpError::InvalidQueryParameter
    })?;
    next_hop_url.set_path(query_pairs.get(format!("{MODOH_RELAYPATH}[1]").as_str()).unwrap());

    // subsequent relays
    for idx in 2..query_pairs.len() / 2 {
      let host_key = format!("{MODOH_RELAYHOST}[{}]", idx - 1);
      let host_val = query_pairs.get(format!("{MODOH_RELAYHOST}[{}]", idx).as_str()).unwrap();
      let path_key = format!("{MODOH_RELAYPATH}[{}]", idx - 1);
      let path_val = query_pairs.get(format!("{MODOH_RELAYPATH}[{}]", idx).as_str()).unwrap();
      next_hop_url.query_pairs_mut().append_pair(&host_key, host_val);
      next_hop_url.query_pairs_mut().append_pair(&path_key, path_val);
    }

    // final destination
    next_hop_url.query_pairs_mut().append_pair(ODOH_TARGETHOST, targethost);
    next_hop_url.query_pairs_mut().append_pair(ODOH_TARGETPATH, targetpath);

    Ok(next_hop_url)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::hyper_client::HttpClient;
  use hyper::{body::Incoming, HeaderMap};
  use std::sync::Arc;

  #[test]
  fn is_looped_test() {
    let url = Url::parse("https://example.com/proxy?targethost=example.com&targetpath=/dns-query").unwrap();
    assert!(is_looped(&url));

    let url = Url::parse(
      "https://example.com/proxy?targethost=example.com&targetpath=/&relayhost[1]=example.com&relaypath[1]=/proxy",
    )
    .unwrap();
    assert!(is_looped(&url));

    let url = Url::parse("https://example.com/proxy?targethost=example.com&targetpath=/dns-query&relayhost[1]=example.com&relaypath[1]=/proxy&relayhost[2]=example.com&relaypath[2]=/proxy").unwrap();
    assert!(is_looped(&url));

    let url = Url::parse("https://example1.com/proxy?targethost=example2.com&targetpath=/dns-query&relayhost[1]=example.com&relaypath[1]=/proxy&relayhost[2]=example.com&relaypath[2]=/proxy").unwrap();
    assert!(is_looped(&url));

    let url = Url::parse("https://example.com/proxy?targethost=example1.com&targetpath=/dns-query&relayhost[1]=example2.com&relaypath[1]=/proxy&relayhost[2]=example.com&relaypath[2]=/proxy").unwrap();
    assert!(is_looped(&url));

    let url = Url::parse("https://example.com/proxy?targethost=example.com&targetpath=/dns-query&relayhost[1]=example1.com&relaypath[1]=/proxy&relayhost[2]=example2.com&relaypath[2]=/proxy").unwrap();
    assert!(is_looped(&url));

    let url = Url::parse("https://example1.com/proxy?targethost=example2.com&targetpath=/dns-query&relayhost[1]=example3.com&relaypath[1]=/proxy&relayhost[2]=example4.com&relaypath[2]=/proxy").unwrap();
    assert!(!is_looped(&url));
  }

  #[test]
  fn test_build_next_hop_url() {
    let runtime_handle = tokio::runtime::Builder::new_multi_thread()
      .build()
      .unwrap()
      .handle()
      .clone();
    let inner: InnerRelay<_, Incoming> = InnerRelay {
      inner: Arc::new(HttpClient::try_new(runtime_handle).unwrap()),
      request_headers: HeaderMap::new(),
      relay_host: "example.com".to_string(),
      relay_path: "/proxy".to_string(),
      max_subseq_nodes: 3,
    };

    let url = Url::parse("https://example.com/proxy?targethost=example1.com&targetpath=/dns-query").unwrap();
    let next_hop_url = inner.build_nexthop_url(&url).unwrap();
    assert_eq!(next_hop_url.as_str(), "https://example1.com/dns-query");

    let url = Url::parse("https://example1.com/proxy?targethost=example2.com&targetpath=/dns-query&relayhost[1]=example3.com&relaypath[1]=/proxy").unwrap();
    let next_hop_url = inner.build_nexthop_url(&url).unwrap();
    assert_eq!(
      next_hop_url.as_str(),
      "https://example3.com/proxy?targethost=example2.com&targetpath=%2Fdns-query"
    );

    let url = Url::parse("https://example1.com/proxy?targethost=example2.com&targetpath=/dns-query&relayhost[1]=example3.com&relaypath[1]=/proxy&relayhost[2]=example4.com&relaypath[2]=/proxy").unwrap();
    let next_hop_url = inner.build_nexthop_url(&url).unwrap();
    assert_eq!(next_hop_url.as_str(), "https://example3.com/proxy?relayhost%5B1%5D=example4.com&relaypath%5B1%5D=%2Fproxy&targethost=example2.com&targetpath=%2Fdns-query");

    let url = Url::parse("https://example1.com/proxy?targethost=example2.com&targetpath=/dns-query&relayhost[1]=example3.com&relaypath[1]=/proxy&relayhost[2]=example4.com&relaypath[2]=/proxy&relayhost[3]=example5.com&relaypath[3]=/proxy").unwrap();
    let next_hop_url = inner.build_nexthop_url(&url);
    assert!(next_hop_url.is_err());
  }
}
