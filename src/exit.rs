pub const EXIT_OK: i32 = 0;
pub const EXIT_SLO: i32 = 4;
pub const EXIT_HTTP: i32 = 22;
pub const EXIT_REDIRECTS: i32 = 47;
pub const EXIT_USAGE: i32 = 64;
pub const EXIT_SOFTWARE: i32 = 70;
pub const EXIT_CANTCREAT: i32 = 73;
pub const EXIT_TEMPFAIL: i32 = 75;
pub const EXIT_SIGINT: i32 = 130;

pub const DEFAULT_TIMEOUT_SECS: f64 = 20.0;
pub const MAX_REDIRECTS: usize = 10;
pub const TLS_PROBE_MAX: std::time::Duration = std::time::Duration::from_secs(5);
pub const CONNECT_PHASE_RATIO: f64 = 0.30;
pub const TLS_PHASE_RATIO: f64 = 0.70;
pub const CERT_EXPIRY_CRITICAL_DAYS: i64 = 30;
pub const CERT_EXPIRY_WARNING_DAYS: i64 = 90;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn user_agent() -> String {
    format!("net-info/{VERSION}")
}
