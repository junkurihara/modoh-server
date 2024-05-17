// use std::sync::Arc;
// use tokio::sync::{mpsc::Receiver, Notify};

pub use tracing::{debug, error, info, warn};

// /// Logging base for query-response
// pub(crate) struct DnsMessageLoggingBase {}

// /// Logger for query-response
// pub(crate) struct DnsMessageLogger {
//   resp_rx: Receiver<()>,
//   term_notify: Arc<Notify>,
// }
