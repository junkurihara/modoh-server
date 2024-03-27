mod constants;
mod error;
mod http_client;
mod parse_md;

use crate::{constants::HTTPSIG_CONFIGS_PATH, error::ModohRegistryError};
use minisign_verify::{PublicKey, Signature};
use std::{borrow::Cow, str::FromStr};

/* ------------------------------------------------ */
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
  pub fn new<'a, T: Into<Cow<'a, str>>>(configs_endpoint_domain: T, dh_signing_target_domain: Option<String>) -> Self {
    let configs_endpoint_uri: http::Uri = format!("https://{}{}", configs_endpoint_domain.into(), HTTPSIG_CONFIGS_PATH)
      .parse()
      .unwrap();
    let dh_signing_target_domain =
      dh_signing_target_domain.unwrap_or_else(|| configs_endpoint_uri.authority().unwrap().to_string());
    Self {
      configs_endpoint_uri,
      dh_signing_target_domain,
    }
  }

  /// Create a new HttpSigDomainInfo by fetching endpoint list in markdown format from `file://<abs_path>` or `https://<domain>/<path>`
  pub async fn new_from_registry_md<'a, T1, T2>(registry_uri: T1, minisign_base64_pk: T2) -> Result<Vec<Self>, ModohRegistryError>
  where
    T1: Into<Cow<'a, str>>,
    T2: Into<Cow<'a, str>>,
  {
    // let registry_uri = registry_uri.into();
    let reqwest_uri = reqwest::Url::from_str(&registry_uri.into()).map_err(|_| ModohRegistryError::FailToParseUrl)?;
    if !reqwest_uri.path().ends_with(".md") {
      return Err(ModohRegistryError::FailToParseUrl);
    }
    let (markdown_input, markdown_minisig_input) = match reqwest_uri.scheme() {
      "file" => {
        let markdown_path = reqwest_uri.to_file_path().map_err(|_| ModohRegistryError::FailToParseUrl)?;
        let markdown_sig_path = markdown_path.with_extension("md.minisig");
        let markdown_input = std::fs::read_to_string(markdown_path)?;
        let markdown_minisig_input = std::fs::read_to_string(markdown_sig_path)?;
        (markdown_input, markdown_minisig_input)
      }
      "https" => {
        let mut reqwest_minisig_uri = reqwest_uri.clone();
        reqwest_minisig_uri.set_path(&format!("{}.minisig", reqwest_uri.path()));
        let client = reqwest::Client::new();
        let futs = vec![client.get(reqwest_uri).send(), client.get(reqwest_minisig_uri).send()];
        let res = futures::future::join_all(futs)
          .await
          .into_iter()
          .collect::<Result<Vec<_>, _>>()?;
        let texts = futures::future::join_all(res.into_iter().map(|v| v.text()))
          .await
          .into_iter()
          .collect::<Result<Vec<_>, _>>()?;
        (texts[0].clone(), texts[1].clone())
      }
      _ => return Err(ModohRegistryError::FailToParseUrl),
    };

    let minisign_pk = minisign_base64_pk.into();
    let pk = PublicKey::from_base64(&minisign_pk)?;
    let sig = Signature::decode(&markdown_minisig_input)?;
    pk.verify(markdown_input.as_bytes(), &sig, false)?;

    let parsed = parse_md::parse_md(markdown_input);
    Ok(parsed)
  }
}

/* ------------------------------------------------ */
#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_works() {
    let minisign_pk = "RWQm8wdk0lJP8AyGtShi96d72ZzkZnGX9gxR0F5EIWmMW2N25SDfzbrt";
    let file_path = std::path::PathBuf::from("../.private/registry/httpsig-endpoints.md");
    let file_path_minisig = std::path::PathBuf::from("../.private/registry/httpsig-endpoints.md.minisig");
    let markdown_input = std::fs::read_to_string(file_path).unwrap();
    let markdown_minisig_input = std::fs::read_to_string(file_path_minisig).unwrap();
    let pk = PublicKey::from_base64(minisign_pk).unwrap();
    let sig = Signature::decode(&markdown_minisig_input).unwrap();
    let res = pk.verify(markdown_input.as_bytes(), &sig, false);
    assert!(res.is_ok());

    let parsed = parse_md::parse_md(markdown_input);
    println!("{:#?}", parsed);
  }

  #[tokio::test]
  async fn test_from_uri() {
    let minisign_pk = "RWQm8wdk0lJP8AyGtShi96d72ZzkZnGX9gxR0F5EIWmMW2N25SDfzbrt";

    let abs_path = std::path::PathBuf::from("../.private/registry/httpsig-endpoints.md")
      .canonicalize()
      .unwrap();
    let string_path = format!("file://{}", abs_path.to_str().unwrap());
    let res = HttpSigDomainInfo::new_from_registry_md(string_path, minisign_pk).await;
    println!("from file:\n{:#?}", res);

    let https_path = "https://filedn.com/lVEKDQEKcCIhnH516GYdXu0/modoh_httpsig_dev/httpsig-endpoints.md";
    let res = HttpSigDomainInfo::new_from_registry_md(https_path, minisign_pk).await;
    println!("from https:\n{:#?}", res);
    assert!(res.is_ok());
  }
}
