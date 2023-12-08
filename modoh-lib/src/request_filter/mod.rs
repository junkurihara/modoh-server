mod domain_filter;
mod ip_filter;

/// RequestFilter filtering inbound and outbound request.
pub struct RequestFilter {
  /// outbound request filter mainly using for domain filtering
  outbound_filter: Option<()>,
  /// inbound request filter mainly using for ip filtering
  inbound_filter: Option<()>,
}
