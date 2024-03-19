mod constants;
mod error;
mod http_client;
mod parse_md;

use constants::HTTPSIG_CONFIGS_PATH;

pub fn ex() {
  println!("Hello, world!");
}

#[derive(Clone, Debug)]
/// HTTP message signatures enabled domain information
pub struct HttpSigDomainInfo {
  /// Configs endpoint
  pub configs_endpoint_uri: http::Uri,
  /// Domain name
  pub dh_signing_target_domain: String,
}
impl HttpSigDomainInfo {
  /// Create a new HttpSigDomainInfo
  pub fn new(configs_endpoint_domain: String, dh_signing_target_domain: Option<String>) -> Self {
    let configs_endpoint_uri: http::Uri = format!("https://{}{}", configs_endpoint_domain, HTTPSIG_CONFIGS_PATH)
      .parse()
      .unwrap();
    let dh_signing_target_domain =
      dh_signing_target_domain.unwrap_or_else(|| configs_endpoint_uri.authority().unwrap().to_string());
    Self {
      configs_endpoint_uri,
      dh_signing_target_domain,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_works() {
    let file_path = std::path::PathBuf::from(".././.private/registry/httpsig-endpoints.md");
    let markdown_input = std::fs::read_to_string(file_path).unwrap();
    let parsed = parse_md::parse_md(markdown_input);
    println!("{:#?}", parsed);
    ex();
  }
}
