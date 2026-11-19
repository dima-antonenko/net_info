use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::dns::Family;

#[derive(Debug, Clone)]
pub enum Verify {
    System,
    Insecure,
    CustomCa(PathBuf),
}

#[derive(Debug, Clone)]
pub enum ProxyChoice {
    Environment,
    Disable,
    Explicit(String),
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub follow: bool,
    pub max_redirects: usize,
    pub timeout: Duration,
    pub http2: bool,
    pub verify: Verify,
    pub proxy: ProxyChoice,
    pub family: Family,
    pub resolve: HashMap<(String, u16), IpAddr>,
    pub env: HashMap<String, String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            follow: false,
            max_redirects: crate::exit::MAX_REDIRECTS,
            timeout: Duration::from_secs_f64(crate::exit::DEFAULT_TIMEOUT_SECS),
            http2: true,
            verify: Verify::System,
            proxy: ProxyChoice::Disable,
            family: Family::Any,
            resolve: HashMap::new(),
            env: HashMap::new(),
        }
    }
}
