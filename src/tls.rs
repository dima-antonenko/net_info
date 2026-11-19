use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Once};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio_rustls::TlsConnector;

use crate::client::ByteStream;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use x509_parser::prelude::*;

use crate::options::Verify;

static CRYPTO: Once = Once::new();

pub fn ensure_crypto() {
    CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug, Clone, Default)]
pub struct TlsMeta {
    pub version: Option<String>,
    pub cipher: Option<String>,
    pub cert_cn: Option<String>,
    pub cert_days_left: Option<i64>,
    pub cert_sans: Vec<String>,
    pub cert_issuer: Option<String>,
    pub cert_serial: Option<String>,
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
}

pub fn client_config(verify: &Verify, http2: bool) -> Result<Arc<ClientConfig>, String> {
    ensure_crypto();
    let mut config = match verify {
        Verify::Insecure => ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
        Verify::System => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        Verify::CustomCa(path) => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            load_pem_certs(path, &mut roots)?;
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
    };
    config.alpn_protocols = if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(Arc::new(config))
}

pub fn load_pem_certs(path: &Path, roots: &mut RootCertStore) -> Result<(), String> {
    let file = File::open(path)
        .map_err(|err| format!("CA bundle file does not exist: {} ({err})", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut added = 0;
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|err| format!("Invalid CA bundle {}: {err}", path.display()))?;
        roots
            .add(cert)
            .map_err(|err| format!("Invalid CA bundle {}: {err}", path.display()))?;
        added += 1;
    }
    if added == 0 {
        return Err(format!(
            "CA bundle {} does not contain a PEM certificate",
            path.display()
        ));
    }
    Ok(())
}

pub struct Handshake {
    pub io: Box<dyn ByteStream>,
    pub meta: TlsMeta,
    pub http2: bool,
    pub tls_ms: f64,
}

pub async fn budgeted_handshake(
    io: Box<dyn ByteStream>,
    host: &str,
    config: Arc<ClientConfig>,
    deadline: Instant,
) -> Result<Handshake, String> {
    let now = Instant::now();
    if now >= deadline {
        return Err("TLS handshake timed out".into());
    }
    let budget = deadline.saturating_duration_since(now);
    let started = Instant::now();
    let connector = TlsConnector::from(config);
    let name = server_name(host)?;
    let stream = tokio::time::timeout(budget, connector.connect(name, io))
        .await
        .map_err(|_| "TLS handshake timed out".to_string())?
        .map_err(|err| format!("TLS handshake failed: {err}"))?;
    let (_, connection) = stream.get_ref();
    let meta = inspect_peer(
        connection.peer_certificates(),
        connection.protocol_version(),
        connection.negotiated_cipher_suite(),
    );
    let http2 = connection.alpn_protocol() == Some(b"h2".as_slice());
    Ok(Handshake {
        io: Box::new(stream),
        meta,
        http2,
        tls_ms: started.elapsed().as_secs_f64() * 1000.0,
    })
}

pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string()).map_err(|err| format!("Invalid TLS server name: {err}"))
}

pub fn inspect_peer(
    certs: Option<&[CertificateDer<'_>]>,
    version: Option<rustls::ProtocolVersion>,
    cipher: Option<rustls::SupportedCipherSuite>,
) -> TlsMeta {
    let mut meta = TlsMeta {
        version: version.map(version_name),
        cipher: cipher.map(cipher_name),
        ..TlsMeta::default()
    };
    if let Some(der) = certs.and_then(|chain| chain.first()) {
        if let Some(parsed) = parse_cert(der.as_ref()) {
            meta.cert_cn = parsed.cert_cn;
            meta.cert_days_left = parsed.cert_days_left;
            meta.cert_sans = parsed.cert_sans;
            meta.cert_issuer = parsed.cert_issuer;
            meta.cert_serial = parsed.cert_serial;
            meta.cert_not_before = parsed.cert_not_before;
            meta.cert_not_after = parsed.cert_not_after;
        }
    }
    meta
}

fn parse_cert(der: &[u8]) -> Option<TlsMeta> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let cert_cn = common_name(cert.subject());
    let cert_issuer = common_name(cert.issuer());
    let cert_sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(dns) => Some((*dns).to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    Some(TlsMeta {
        cert_cn,
        cert_issuer,
        cert_sans,
        cert_serial: Some(hex_encode(cert.raw_serial())),
        cert_not_before: Some(unix_to_iso(not_before)),
        cert_not_after: Some(unix_to_iso(not_after)),
        cert_days_left: Some((not_after - now).div_euclid(86_400)),
        ..TlsMeta::default()
    })
}

fn common_name(name: &X509Name) -> Option<String> {
    name.iter_common_name().next().and_then(|cn| {
        cn.as_str()
            .ok()
            .map(str::to_string)
            .or_else(|| String::from_utf8(cn.as_slice().to_vec()).ok())
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn unix_to_iso(secs: i64) -> String {
    let (days, tod) = if secs >= 0 {
        (secs.div_euclid(86_400), secs.rem_euclid(86_400))
    } else {
        (secs.div_euclid(86_400), secs.rem_euclid(86_400))
    };
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00")
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year as i32, month as u32, day as u32)
}

fn version_name(version: rustls::ProtocolVersion) -> String {
    match version {
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".into(),
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".into(),
        other => format!("{other:?}"),
    }
}

fn cipher_name(suite: rustls::SupportedCipherSuite) -> String {
    use rustls::CipherSuite;
    match suite.suite() {
        CipherSuite::TLS13_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        CipherSuite::TLS13_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        other => return format!("{other:?}"),
    }
    .to_string()
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_unix_epoch() {
        assert_eq!(unix_to_iso(0), "1970-01-01T00:00:00+00:00");
    }
}
