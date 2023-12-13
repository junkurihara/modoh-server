use crate::AccessConfig;

use self::ip_filter::IpFilter;
mod domain_filter;
mod ip_filter;

/// RequestFilter filtering inbound and outbound request.
pub struct RequestFilter {
  /// outbound request filter mainly using for domain filtering
  pub outbound_filter: Option<()>,
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
    Self {
      outbound_filter: None,
      inbound_filter,
    }
  }
}
