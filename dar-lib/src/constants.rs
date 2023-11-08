pub const LISTEN_SOCKET: &str = "0.0.0.0:8080";
pub const HOSTNAME: &str = "localhost";
pub const PATH: &str = "/proxy";

pub const TCP_LISTEN_BACKLOG: u32 = 1024;
pub const MAX_CLIENTS: usize = 1024;
pub const MAX_CONCURRENT_STREAMS: u32 = 100;
pub const KEEPALIVE: bool = true;
