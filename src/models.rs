use serde_json::{Map, Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            "HEAD" => Some(Self::Head),
            "OPTIONS" => Some(Self::Options),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TimingMetrics {
    pub dns_ms: f64,
    pub connect_ms: f64,
    pub tls_ms: f64,
    pub ttfb_ms: f64,
    pub total_ms: f64,
    pub wait_ms: f64,
    pub xfer_ms: f64,
    pub is_estimated: bool,
    pub connect_measured: bool,
    pub tls_measured: bool,
}

impl Default for TimingMetrics {
    fn default() -> Self {
        Self {
            dns_ms: 0.0,
            connect_ms: 0.0,
            tls_ms: 0.0,
            ttfb_ms: 0.0,
            total_ms: 0.0,
            wait_ms: 0.0,
            xfer_ms: 0.0,
            is_estimated: false,
            connect_measured: false,
            tls_measured: false,
        }
    }
}

impl TimingMetrics {
    /// Fill `wait_ms` and `xfer_ms`. When connect/TLS were not measured on
    /// HTTPS, split the gap between DNS and TTFB 30/70.
    pub fn finalize(&mut self, is_https: bool) {
        if !self.connect_measured && (!is_https || !self.tls_measured) {
            let connection_phase = (self.ttfb_ms - self.dns_ms).max(0.0);
            if is_https {
                self.connect_ms = connection_phase * crate::exit::CONNECT_PHASE_RATIO;
                self.tls_ms = connection_phase * crate::exit::TLS_PHASE_RATIO;
                self.is_estimated = true;
            } else {
                self.connect_ms = connection_phase;
                self.tls_ms = 0.0;
                self.is_estimated = false;
            }
        }
        self.wait_ms = (self.ttfb_ms - (self.dns_ms + self.connect_ms + self.tls_ms)).max(0.0);
        self.xfer_ms = (self.total_ms - self.ttfb_ms).max(0.0);
    }

    pub fn phase(&self, key: &str) -> Option<f64> {
        Some(match key {
            "dns" => self.dns_ms,
            "connect" => self.connect_ms,
            "tls" => self.tls_ms,
            "ttfb" => self.ttfb_ms,
            "wait" => self.wait_ms,
            "xfer" => self.xfer_ms,
            "total" => self.total_ms,
            _ => return None,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "dns_ms": self.dns_ms,
            "connect_ms": self.connect_ms,
            "tls_ms": self.tls_ms,
            "ttfb_ms": self.ttfb_ms,
            "total_ms": self.total_ms,
            "wait_ms": self.wait_ms,
            "xfer_ms": self.xfer_ms,
            "is_estimated": self.is_estimated,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkInfo {
    pub ip: Option<String>,
    pub ip_family: Option<String>,
    pub http_version: Option<String>,
    pub tls_version: Option<String>,
    pub tls_cipher: Option<String>,
    pub cert_cn: Option<String>,
    pub cert_days_left: Option<i64>,
    pub cert_sans: Vec<String>,
    pub cert_issuer: Option<String>,
    pub cert_serial: Option<String>,
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
    pub tls_verified: Option<bool>,
    pub tls_custom_ca: Option<bool>,
    pub proxy_url: Option<String>,
    pub proxy_source: Option<String>,
}

impl Default for NetworkInfo {
    fn default() -> Self {
        Self {
            ip: None,
            ip_family: None,
            http_version: None,
            tls_version: None,
            tls_cipher: None,
            cert_cn: None,
            cert_days_left: None,
            cert_sans: Vec::new(),
            cert_issuer: None,
            cert_serial: None,
            cert_not_before: None,
            cert_not_after: None,
            tls_verified: None,
            tls_custom_ca: None,
            proxy_url: None,
            proxy_source: None,
        }
    }
}

impl NetworkInfo {
    pub fn to_json(&self) -> Value {
        json!({
            "ip": self.ip,
            "ip_family": self.ip_family,
            "http_version": self.http_version,
            "tls_version": self.tls_version,
            "tls_cipher": self.tls_cipher,
            "cert_cn": self.cert_cn,
            "cert_days_left": self.cert_days_left,
            "cert_sans": self.cert_sans,
            "cert_issuer": self.cert_issuer,
            "cert_serial": self.cert_serial,
            "cert_not_before": self.cert_not_before,
            "cert_not_after": self.cert_not_after,
            "tls_verified": self.tls_verified,
            "tls_custom_ca": self.tls_custom_ca,
            "proxy_url": self.proxy_url,
            "proxy_source": self.proxy_source,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResponseInfo {
    pub status: Option<u16>,
    pub bytes: u64,
    pub content_type: Option<String>,
    pub server: Option<String>,
    pub date: Option<String>,
    pub location: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl Default for ResponseInfo {
    fn default() -> Self {
        Self {
            status: None,
            bytes: 0,
            content_type: None,
            server: None,
            date: None,
            location: None,
            headers: Vec::new(),
        }
    }
}

impl ResponseInfo {
    pub fn to_json(&self) -> Value {
        let mut headers = Map::new();
        for (name, value) in &self.headers {
            headers.insert(name.clone(), Value::String(value.clone()));
        }
        json!({
            "status": self.status,
            "bytes": self.bytes,
            "content_type": self.content_type,
            "server": self.server,
            "date": self.date,
            "location": self.location,
            "headers": headers,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StepMetrics {
    pub url: String,
    pub step_number: usize,
    pub timing: TimingMetrics,
    pub network: NetworkInfo,
    pub response: ResponseInfo,
    pub error: Option<String>,
    pub error_kind: Option<String>,
    pub note: Option<String>,
    pub proxied_via: Option<String>,
    pub request_method: Option<String>,
    pub request_headers: Vec<(String, String)>,
    pub request_body_bytes: u64,
    pub redirect_limit_reached: bool,
}

impl StepMetrics {
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.response.status, Some(status) if (300..400).contains(&status))
            && self.response.location.is_some()
    }

    pub fn to_json(&self) -> Value {
        let mut request_headers = Map::new();
        for (name, value) in &self.request_headers {
            request_headers.insert(name.clone(), Value::String(value.clone()));
        }
        json!({
            "url": self.url,
            "step_number": self.step_number,
            "request": {
                "method": self.request_method,
                "headers": request_headers,
                "body_bytes": self.request_body_bytes,
            },
            "timing": self.timing.to_json(),
            "network": self.network.to_json(),
            "response": self.response.to_json(),
            "error": self.error,
            "note": self.note,
            "redirect_limit_reached": self.redirect_limit_reached,
            "proxy": self.proxied_via,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_wait_and_transfer() {
        let mut timing = TimingMetrics {
            dns_ms: 10.0,
            connect_ms: 20.0,
            tls_ms: 50.0,
            ttfb_ms: 100.0,
            total_ms: 150.0,
            connect_measured: true,
            tls_measured: true,
            ..TimingMetrics::default()
        };
        timing.finalize(true);
        assert!((timing.wait_ms - 20.0).abs() < f64::EPSILON);
        assert!((timing.xfer_ms - 50.0).abs() < f64::EPSILON);
        assert!(!timing.is_estimated);
    }

    #[test]
    fn estimates_https_when_phases_were_not_measured() {
        let mut timing = TimingMetrics {
            dns_ms: 10.0,
            ttfb_ms: 110.0,
            total_ms: 110.0,
            ..TimingMetrics::default()
        };
        timing.finalize(true);
        assert!(timing.is_estimated);
        assert!((timing.connect_ms - 30.0).abs() < 1e-9);
        assert!((timing.tls_ms - 70.0).abs() < 1e-9);
        assert!((timing.wait_ms).abs() < 1e-9);
    }
}
