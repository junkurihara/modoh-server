pub const LISTEN_SOCKET: &str = "0.0.0.0:8080";
pub const HOSTNAME: &str = "localhost";
pub const PATH: &str = "/proxy";

pub const TCP_LISTEN_BACKLOG: u32 = 1024;
pub const MAX_CLIENTS: usize = 1024;
pub const MAX_CONCURRENT_STREAMS: u32 = 100;
pub const KEEPALIVE: bool = true;
pub const TIMEOUT: u64 = 3;

// ODoH and MODoH constants

pub const FORWARDER_UA: &str = "doh-auth-relay";
pub const ODOH_CONTENT_TYPE: &str = "application/oblivious-dns-message";
pub const ODOH_ACCEPT: &str = "application/oblivious-dns-message";
pub const ODOH_CACHE_CONTROL: &str = "no-cache, no-store";
pub const MODOH_MAX_SUBSEQ_NODES: usize = 3;

/// Maximum length of a DNS query in bytes, an encrypted query as well
pub const MAX_DNS_QUESTION_LEN: usize = 512;

// Auth

/// JWKS refetch delay in seconds for authentication
pub const JWKS_REFETCH_DELAY_SEC: u64 = 300;
pub const JWKS_ENDPOINT_PATH: &str = "jwks";
