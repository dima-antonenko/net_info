use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Any,
    V4,
    V6,
}

#[derive(Debug, Clone)]
pub struct Lookup {
    pub addresses: Vec<SocketAddr>,
    pub dns_ms: f64,
}

pub fn family_label(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() { "IPv4" } else { "IPv6" }
}

pub async fn lookup(
    host: &str,
    port: u16,
    family: Family,
    timeout: Duration,
) -> Result<Lookup, String> {
    let started = Instant::now();
    let resolver = TokioResolver::builder_tokio()
        .map_err(|err| format!("DNS resolver setup failed: {err}"))?
        .build()
        .map_err(|err| format!("DNS resolver setup failed: {err}"))?;
    let query = tokio::time::timeout(timeout, resolver.lookup_ip(host))
        .await
        .map_err(|_| format!("DNS resolution failed for {host}: timed out"))?
        .map_err(|err| format!("DNS resolution failed for {host}: {err}"))?;
    let addresses = query
        .iter()
        .filter(|ip| match family {
            Family::Any => true,
            Family::V4 => ip.is_ipv4(),
            Family::V6 => ip.is_ipv6(),
        })
        .map(|ip| SocketAddr::new(ip, port))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        let kind = match family {
            Family::Any => "address",
            Family::V4 => "IPv4 address",
            Family::V6 => "IPv6 address",
        };
        return Err(format!("DNS resolution failed for {host}: no {kind}"));
    }
    Ok(Lookup {
        addresses,
        dns_ms: elapsed_ms(started),
    })
}

pub fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

pub fn wire_host(host: &str) -> Result<String, String> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(host.to_string());
    }
    idna::domain_to_ascii(host).map_err(|err| format!("Invalid host '{host}': {err}"))
}
