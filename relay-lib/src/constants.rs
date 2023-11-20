pub const LISTEN_SOCKET: &str = "0.0.0.0:8080";
pub const HOSTNAME: &str = "localhost";
pub const RELAY_PATH: &str = "/proxy";
pub const TARGET_PATH: &str = "/dns-query";
pub const ODOH_CONFIGS_PATH: &str = "/.well-known/odohconfigs";

pub const TCP_LISTEN_BACKLOG: u32 = 1024;
pub const MAX_CLIENTS: usize = 1024;
pub const MAX_CONCURRENT_STREAMS: u32 = 100;
pub const KEEPALIVE: bool = true;
pub const TIMEOUT: u64 = 3;

// for ODoH target

pub const UPSTREAM: &str = "8.8.8.8:53";
pub const ERROR_TTL: u32 = 2;
pub const MAX_TTL: u32 = 604800;
pub const MIN_TTL: u32 = 10;
pub const STALE_IF_ERROR_SECS: u32 = 86400;
pub const STALE_WHILE_REVALIDATE_SECS: u32 = 60;

// ODoH and MODoH constants

pub const FORWARDER_USER_AGENT: &str = "doh-auth-relay";
pub const VALIDATOR_USER_AGENT: &str = "doh-auth-relay";
pub const ODOH_CONTENT_TYPE: &str = "application/oblivious-dns-message";
pub const ODOH_ACCEPT: &str = "application/oblivious-dns-message";
pub const ODOH_CACHE_CONTROL: &str = "no-cache, no-store";
pub const MODOH_MAX_SUBSEQ_NODES: usize = 3;

pub const ODOH_KEY_ROTATION_SECS: u64 = 86400;

/// Maximum length of a DNS query in bytes, an encrypted query as well
pub const MAX_DNS_QUESTION_LEN: usize = 512;

// Validation

/// JWKS refetch delay in seconds for validation
pub const JWKS_REFETCH_DELAY_SEC: u64 = 300;
/// HTTP request timeout for refetching JWKS
pub const JWKS_REFETCH_TIMEOUT_SEC: u64 = 3;
/// Expected maximum size of JWKS in bytes
pub const EXPECTED_MAX_JWKS_SIZE: u64 = 1024 * 64;
