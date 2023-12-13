mod domain_filter;
mod ip_filter;

use self::{domain_filter::DomainFilter, ip_filter::IpFilter};
use crate::AccessConfig;

/// RequestFilter filtering inbound and outbound request.
pub struct RequestFilter {
  /// outbound request filter mainly using for domain filtering
  pub outbound_filter: Option<DomainFilter>,
  /// inbound request filter mainly using for ip filtering
  pub inbound_filter: Option<IpFilter>,
}

impl RequestFilter {
  /// Create new RequestFilter
  pub(crate) fn new(access_config: &AccessConfig) -> Self {
    let inbound_filter = if !access_config.allowed_source_ip_addresses.is_empty() {
      Some(IpFilter::new(access_config))
    } else {
      None
    };
    let outbound_filter = if !access_config.allowed_destination_domains.is_empty() {
      Some(DomainFilter::new(access_config.allowed_destination_domains.clone()))
    } else {
      None
    };
    Self {
      outbound_filter,
      inbound_filter,
    }
  }
}
