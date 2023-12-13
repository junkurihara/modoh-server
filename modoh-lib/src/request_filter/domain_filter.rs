use crate::log::*;
use cedarwood::Cedar;
use regex::Regex;

/// Domain filter supporting prefix and suffix matching
pub(crate) struct DomainFilter {
  prefix_cedar: Cedar,
  suffix_cedar: Cedar,
  prefix_dict: Vec<String>,
  suffix_dict: Vec<String>,
}

/// Regex for domain or prefix matching
const REGEXP_DOMAIN_OR_PREFIX: &str = r"^([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.)+([a-zA-Z]{2,}|\*)";

/// Support function for reverse string
fn reverse_string(text: &str) -> String {
  text.chars().rev().collect::<String>()
}

impl DomainFilter {
  /// Create new domain filter
  pub(crate) fn new(allowed_domains: Vec<String>) -> Self {
    let start_with_star = Regex::new(r"^\*\..+").unwrap();
    let end_with_star = Regex::new(r".+\.\*$").unwrap();
    // TODO: currently either one of prefix or suffix match with '*' is supported
    let re = Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN_OR_PREFIX, r"$")).unwrap();
    let dict: Vec<String> = allowed_domains
      .iter()
      .map(|d| if start_with_star.is_match(d) { &d[2..] } else { d })
      .filter(|x| re.is_match(x) || (x.split('.').count() == 1))
      .map(|y| y.to_ascii_lowercase())
      .collect();
    let prefix_dict: Vec<String> = dict
      .iter()
      .filter(|d| end_with_star.is_match(d))
      .map(|d| d[..d.len() - 2].to_string())
      .collect();
    let suffix_dict: Vec<String> = dict
      .iter()
      .filter(|d| !end_with_star.is_match(d))
      .map(|d| reverse_string(d))
      .collect();

    let prefix_kv: Vec<(&str, i32)> = prefix_dict
      .iter()
      .map(AsRef::as_ref)
      .enumerate()
      .map(|(k, s)| (s, k as i32))
      .collect();
    let mut prefix_cedar = Cedar::new();
    prefix_cedar.build(&prefix_kv);

    let suffix_kv: Vec<(&str, i32)> = suffix_dict
      .iter()
      .map(AsRef::as_ref)
      .enumerate()
      .map(|(k, s)| (s, k as i32))
      .collect();
    let mut suffix_cedar = Cedar::new();
    suffix_cedar.build(&suffix_kv);

    Self {
      prefix_cedar,
      suffix_cedar,
      prefix_dict,
      suffix_dict,
    }
  }

  /// Check if the domain name is in the list by suffix/exact matching
  fn find_suffix_match(&self, query_domain: &str) -> bool {
    let rev_nn = reverse_string(query_domain);
    let matched_items = self
      .suffix_cedar
      .common_prefix_iter(&rev_nn)
      .map(|(x, _)| self.suffix_dict[x as usize].clone());

    let mut matched_as_domain = matched_items.filter(|found| {
      if found.len() == rev_nn.len() {
        true
      } else if let Some(nth) = rev_nn.chars().nth(found.chars().count()) {
        nth.to_string() == "."
      } else {
        false
      }
    });
    matched_as_domain.next().is_some()
  }

  /// Check if the domain name is in the list by prefix matching
  fn find_prefix_match(&self, query_domain: &str) -> bool {
    let matched_items = self
      .prefix_cedar
      .common_prefix_iter(query_domain)
      .map(|(x, _)| self.prefix_dict[x as usize].clone());

    let mut matched_as_domain = matched_items.filter(|found| {
      if let Some(nth) = query_domain.chars().nth(found.chars().count()) {
        nth.to_string() == "."
      } else {
        false
      }
    });
    matched_as_domain.next().is_some()
  }

  pub fn in_domain_list(&self, domain_name: &str) -> bool {
    // remove final dot
    let nn = domain_name.to_ascii_lowercase();

    if self.find_suffix_match(&nn) {
      debug!("[with cw] suffix/exact match found: {}", nn);
      return true;
    }

    if self.find_prefix_match(&nn) {
      debug!("[with cw] prefix match found: {}", nn);
      return true;
    }

    // TODO: other matching patterns
    false
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn domain_filter_works() {
    let allowed_domains = vec![
      "www.google.com".to_string(),
      "www.yahoo.com".to_string(),
      "*.google.com".to_string(),
      "*.yahoo.com".to_string(),
      "google.com".to_string(),
      "yahoo.com".to_string(),
    ];
    let domain_filter = DomainFilter::new(allowed_domains);

    let query = "www.google.com";
    assert!(domain_filter.in_domain_list(query));

    let query = "www.yahoo.com";
    assert!(domain_filter.in_domain_list(query));

    let query = "any.www.google.com";
    assert!(domain_filter.in_domain_list(query));

    let query = "any.yahoo.com";
    assert!(domain_filter.in_domain_list(query));

    let query = "googlee.com";
    assert!(!domain_filter.in_domain_list(query));
  }
}
