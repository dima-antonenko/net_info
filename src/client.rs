use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> ByteStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type Io = Box<dyn ByteStream>;

use crate::dns::{self, Family, elapsed_ms, family_label};
use crate::exit::user_agent;
use crate::models::{Method, NetworkInfo, ResponseInfo, TimingMetrics};
use crate::options::{Settings, Verify};
use crate::proxy::{self, EffectiveProxy};
use crate::redact::{percent_decode, redact_url_credentials, sanitize_headers};
use crate::tls::{self, TlsMeta};
use url::Url;

pub struct Outcome {
    pub timing: TimingMetrics,
    pub network: NetworkInfo,
    pub response: ResponseInfo,
}

pub struct RequestError {
    pub message: String,
    pub network: NetworkInfo,
    pub response: Option<ResponseInfo>,
    pub timing: TimingMetrics,
    pub kind: &'static str,
}

struct Session {
    io: Io,
    dns_ms: f64,
    connect_ms: f64,
    tls_ms: f64,
    ip: Option<IpAddr>,
    family: Option<String>,
    tls: TlsMeta,
    http2: bool,
    absolute_form: bool,
    proxy_authorization: Option<String>,
}

struct RawResponse {
    status: u16,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
    ttfb: Instant,
    end: Instant,
}

pub async fn perform(
    url: &Url,
    method: Method,
    body: Option<&[u8]>,
    headers: &[(String, String)],
    deadline: Instant,
    settings: &Settings,
) -> Result<Outcome, RequestError> {
    let started = Instant::now();
    let is_https = url.scheme() == "https";
    let host = match url.host_str() {
        Some(host) => host.to_string(),
        None => {
            return fail(
                "Invalid URL: missing host".into(),
                NetworkInfo::default(),
                None,
                TimingMetrics::default(),
            );
        }
    };
    let port = url
        .port_or_known_default()
        .unwrap_or(if is_https { 443 } else { 80 });
    let wire_host = match dns::wire_host(&host) {
        Ok(host) => host,
        Err(err) => {
            return fail(err, NetworkInfo::default(), None, TimingMetrics::default());
        }
    };

    let mut network = NetworkInfo::default();
    let effective = match proxy::resolve_effective_proxy(
        &settings.proxy,
        url.scheme(),
        &host,
        &settings.env,
    ) {
        Ok(effective) => effective,
        Err(err) => return fail(err, network, None, TimingMetrics::default()),
    };
    network.proxy_url = effective
        .url
        .as_deref()
        .map(redact_url_credentials);
    network.proxy_source = effective.source.clone();
    if is_https {
        network.tls_verified = Some(!matches!(settings.verify, Verify::Insecure));
        if matches!(settings.verify, Verify::CustomCa(_)) {
            network.tls_custom_ca = Some(true);
        }
    }

    let session = match dial(
        url,
        &host,
        &wire_host,
        port,
        is_https,
        deadline,
        settings,
        &effective,
    )
    .await
    {
        Ok(session) => session,
        Err(err) => {
            network.ip = err.ip.map(|ip| ip.to_string());
            network.ip_family = err.family;
            apply_tls(&mut network, &err.tls);
            let mut timing = TimingMetrics {
                dns_ms: err.dns_ms,
                connect_ms: err.connect_ms,
                tls_ms: err.tls_ms,
                ttfb_ms: elapsed_ms(started),
                total_ms: elapsed_ms(started),
                connect_measured: err.connect_ms > 0.0,
                tls_measured: err.tls_ms > 0.0,
                ..TimingMetrics::default()
            };
            timing.finalize(is_https);
            return fail(err.message, network, None, timing);
        }
    };

    network.ip = session.ip.map(|ip| ip.to_string());
    network.ip_family = session.family.clone();
    apply_tls(&mut network, &session.tls);

    let response = match dispatch(
        session.io,
        build_request(
            url,
            method,
            body,
            headers,
            session.absolute_form || session.http2,
            session.proxy_authorization.as_deref(),
        ),
        session.http2,
        method,
        deadline,
    )
    .await
    {
        Ok(response) => response,
        Err(message) => {
            let mut timing = TimingMetrics {
                dns_ms: session.dns_ms,
                connect_ms: session.connect_ms,
                tls_ms: session.tls_ms,
                ttfb_ms: elapsed_ms(started),
                total_ms: elapsed_ms(started),
                connect_measured: true,
                tls_measured: is_https,
                ..TimingMetrics::default()
            };
            timing.finalize(is_https);
            return fail(message, network, None, timing);
        }
    };

    network.http_version = Some(version_name(response.version));
    let info = response_info(&response, method);
    let mut timing = TimingMetrics {
        dns_ms: session.dns_ms,
        connect_ms: session.connect_ms,
        tls_ms: session.tls_ms,
        ttfb_ms: response.ttfb.duration_since(started).as_secs_f64() * 1000.0,
        total_ms: response.end.duration_since(started).as_secs_f64() * 1000.0,
        connect_measured: true,
        tls_measured: is_https,
        ..TimingMetrics::default()
    };
    timing.finalize(is_https);
    Ok(Outcome {
        timing,
        network,
        response: info,
    })
}

struct DialError {
    message: String,
    ip: Option<IpAddr>,
    family: Option<String>,
    dns_ms: f64,
    connect_ms: f64,
    tls_ms: f64,
    tls: TlsMeta,
}

async fn dial(
    url: &Url,
    host: &str,
    wire_host: &str,
    port: u16,
    is_https: bool,
    deadline: Instant,
    settings: &Settings,
    effective: &EffectiveProxy,
) -> Result<Session, DialError> {
    if let Some(proxy_url) = &effective.url {
        let proxy = Url::parse(proxy_url).map_err(|err| dial_err(err.to_string()))?;
        return match proxy.scheme() {
            "socks5" => {
                dial_socks(
                    url,
                    host,
                    wire_host,
                    port,
                    is_https,
                    deadline,
                    settings,
                    &proxy,
                    false,
                )
                .await
            }
            "socks5h" => {
                dial_socks(
                    url,
                    host,
                    wire_host,
                    port,
                    is_https,
                    deadline,
                    settings,
                    &proxy,
                    true,
                )
                .await
            }
            "http" | "https" => {
                dial_http_proxy(
                    wire_host,
                    port,
                    is_https,
                    deadline,
                    settings,
                    &proxy,
                )
                .await
            }
            other => Err(dial_err(format!("unsupported proxy scheme '{other}'"))),
        };
    }
    dial_direct(host, wire_host, port, is_https, deadline, settings).await
}

async fn dial_direct(
    host: &str,
    wire_host: &str,
    port: u16,
    is_https: bool,
    deadline: Instant,
    settings: &Settings,
) -> Result<Session, DialError> {
    let (addresses, dns_ms) = match resolve_target(host, port, settings, deadline).await {
        Ok(resolved) => resolved,
        Err(message) => return Err(dial_err(message)),
    };
    let mut error = dial_err("Connection failed".into());
    error.dns_ms = dns_ms;
    let attempts_started = Instant::now();
    for (index, address) in addresses.iter().enumerate() {
        error.ip = Some(address.ip());
        error.family = Some(family_label(address.ip()).into());
        let failed_ms = elapsed_ms(attempts_started);
        let budget = match slice_budget(deadline, addresses.len() - index) {
            Ok(budget) => budget,
            Err(message) => {
                error.message = message;
                return Err(error);
            }
        };
        let tcp_started = Instant::now();
        let stream = match connect_tcp(*address, budget).await {
            Ok(stream) => stream,
            Err(message) => {
                error.message = message;
                error.connect_ms = elapsed_ms(attempts_started);
                continue;
            }
        };
        let tcp_ms = elapsed_ms(tcp_started);
        let connect_ms = failed_ms + tcp_ms;
        if !is_https {
            return Ok(plain_session(
                Box::new(stream),
                dns_ms,
                connect_ms,
                Some(address.ip()),
            ));
        }
        let config = match tls::client_config(&settings.verify, settings.http2) {
            Ok(config) => config,
            Err(message) => return Err(dial_err(message)),
        };
        match tls::budgeted_handshake(Box::new(stream), wire_host, config, deadline).await {
            Ok(tls) => {
                return Ok(Session {
                    io: tls.io,
                    dns_ms,
                    connect_ms,
                    tls_ms: tls.tls_ms,
                    ip: Some(address.ip()),
                    family: Some(family_label(address.ip()).into()),
                    tls: tls.meta,
                    http2: tls.http2 && settings.http2,
                    absolute_form: false,
                    proxy_authorization: None,
                });
            }
            Err(message) => {
                error.message = message;
                error.connect_ms = connect_ms;
                if !matches!(settings.verify, Verify::Insecure) {
                    error.tls = probe_certificate(*address, wire_host, deadline).await;
                }
                return Err(error);
            }
        }
    }
    Err(error)
}

async fn dial_http_proxy(
    wire_host: &str,
    port: u16,
    is_https: bool,
    deadline: Instant,
    settings: &Settings,
    proxy: &Url,
) -> Result<Session, DialError> {
    let started = Instant::now();
    let auth = proxy_basic_auth(proxy);
    let mut io = match connect_proxy(proxy, deadline, settings).await {
        Ok(io) => io,
        Err(message) => return Err(dial_err(message)),
    };
    if is_https {
        let target = connect_authority(wire_host, port);
        if let Err(message) = http_connect(&mut io, &target, auth.as_deref(), deadline).await {
            let mut error = dial_err(message);
            error.connect_ms = elapsed_ms(started);
            return Err(error);
        }
        let connect_ms = elapsed_ms(started);
        let config = match tls::client_config(&settings.verify, settings.http2) {
            Ok(config) => config,
            Err(message) => return Err(dial_err(message)),
        };
        match tls::budgeted_handshake(io, wire_host, config, deadline).await {
            Ok(tls) => {
                return Ok(Session {
                    io: tls.io,
                    dns_ms: 0.0,
                    connect_ms,
                    tls_ms: tls.tls_ms,
                    ip: None,
                    family: None,
                    tls: tls.meta,
                    http2: tls.http2 && settings.http2,
                    absolute_form: false,
                    proxy_authorization: None,
                });
            }
            Err(message) => {
                let mut error = dial_err(message);
                error.connect_ms = connect_ms;
                return Err(error);
            }
        }
    }
    Ok(Session {
        io,
        dns_ms: 0.0,
        connect_ms: elapsed_ms(started),
        tls_ms: 0.0,
        ip: None,
        family: None,
        tls: TlsMeta::default(),
        http2: false,
        absolute_form: true,
        proxy_authorization: auth,
    })
}

async fn dial_socks(
    _url: &Url,
    host: &str,
    wire_host: &str,
    port: u16,
    is_https: bool,
    deadline: Instant,
    settings: &Settings,
    proxy: &Url,
    remote_dns: bool,
) -> Result<Session, DialError> {
    let auth = proxy_user(proxy);
    if remote_dns {
        return match finish_socks(
            proxy,
            SocksDest::Name(wire_host.to_string(), port),
            None,
            0.0,
            is_https,
            wire_host,
            deadline,
            settings,
            auth,
        )
        .await
        {
            Ok(session) => Ok(session),
            Err(message) => Err(dial_err(message)),
        };
    }

    let (addresses, dns_ms) = match resolve_target(host, port, settings, deadline).await {
        Ok(resolved) => resolved,
        Err(message) => return Err(dial_err(message)),
    };
    let mut error = dial_err("SOCKS connection failed".into());
    error.dns_ms = dns_ms;
    let attempts_started = Instant::now();
    for address in &addresses {
        error.ip = Some(address.ip());
        error.family = Some(family_label(address.ip()).into());
        match finish_socks(
            proxy,
            SocksDest::Addr(*address),
            Some(address.ip()),
            dns_ms + elapsed_ms(attempts_started),
            is_https,
            wire_host,
            deadline,
            settings,
            auth.clone(),
        )
        .await
        {
            Ok(mut session) => {
                session.dns_ms = dns_ms;
                session.connect_ms = elapsed_ms(attempts_started);
                return Ok(session);
            }
            Err(message) if message.starts_with("TLS ") => {
                error.message = message;
                error.connect_ms = elapsed_ms(attempts_started);
                return Err(error);
            }
            Err(message) => {
                error.message = message;
                error.connect_ms = elapsed_ms(attempts_started);
            }
        }
    }
    Err(error)
}

enum SocksDest {
    Addr(SocketAddr),
    Name(String, u16),
}

async fn finish_socks(
    proxy: &Url,
    dest: SocksDest,
    ip: Option<IpAddr>,
    failed_before_ms: f64,
    is_https: bool,
    wire_host: &str,
    deadline: Instant,
    settings: &Settings,
    auth: Option<(String, String)>,
) -> Result<Session, String> {
    let started = Instant::now();
    let stream = match connect_proxy_tcp(proxy, deadline).await {
        Ok(stream) => stream,
        Err(message) => return Err(message),
    };
    let socks = socks_handshake(stream, &dest, auth.as_ref()).await?;
    let connect_ms = failed_before_ms + elapsed_ms(started);
    if !is_https {
        return Ok(Session {
            io: socks,
            dns_ms: 0.0,
            connect_ms,
            tls_ms: 0.0,
            ip,
            family: ip.map(|ip| family_label(ip).into()),
            tls: TlsMeta::default(),
            http2: false,
            absolute_form: false,
            proxy_authorization: None,
        });
    }
    let config = tls::client_config(&settings.verify, settings.http2)?;
    let tls = tls::budgeted_handshake(socks, wire_host, config, deadline).await?;
    Ok(Session {
        io: tls.io,
        dns_ms: 0.0,
        connect_ms,
        tls_ms: tls.tls_ms,
        ip,
        family: ip.map(|ip| family_label(ip).into()),
        tls: tls.meta,
        http2: tls.http2 && settings.http2,
        absolute_form: false,
        proxy_authorization: None,
    })
}

async fn socks_handshake(
    stream: TcpStream,
    dest: &SocksDest,
    auth: Option<&(String, String)>,
) -> Result<Io, String> {
    use tokio_socks::tcp::Socks5Stream;
    let result = match (dest, auth) {
        (SocksDest::Addr(address), Some((user, password))) => {
            Socks5Stream::connect_with_password_and_socket(stream, *address, user, password).await
        }
        (SocksDest::Addr(address), None) => {
            Socks5Stream::connect_with_socket(stream, *address).await
        }
        (SocksDest::Name(host, port), Some((user, password))) => {
            Socks5Stream::connect_with_password_and_socket(
                stream,
                (host.as_str(), *port),
                user,
                password,
            )
            .await
        }
        (SocksDest::Name(host, port), None) => {
            Socks5Stream::connect_with_socket(stream, (host.as_str(), *port)).await
        }
    };
    match result {
        Ok(stream) => Ok(Box::new(stream)),
        Err(err) => Err(format!("SOCKS5 handshake failed: {err}")),
    }
}

async fn connect_proxy(proxy: &Url, deadline: Instant, settings: &Settings) -> Result<Io, String> {
    let host = proxy
        .host_str()
        .ok_or_else(|| "Proxy URL is missing a host".to_string())?;
    let stream = connect_proxy_tcp(proxy, deadline).await?;
    if proxy.scheme() == "https" {
        let config = tls::client_config(&settings.verify, false)?;
        let tls = tls::budgeted_handshake(Box::new(stream), host, config, deadline).await?;
        Ok(tls.io)
    } else {
        Ok(Box::new(stream))
    }
}

async fn connect_proxy_tcp(proxy: &Url, deadline: Instant) -> Result<TcpStream, String> {
    let host = proxy
        .host_str()
        .ok_or_else(|| "Proxy URL is missing a host".to_string())?;
    let port = proxy.port().unwrap_or(match proxy.scheme() {
        "https" => 443,
        "http" => 80,
        _ => 1080,
    });
    let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        let wire = dns::wire_host(host)?;
        dns::lookup(&wire, port, Family::Any, budget(deadline)?)
            .await?
            .addresses
    };
    let mut last = "Proxy connection failed".to_string();
    for (index, address) in addresses.iter().enumerate() {
        let Ok(slice) = slice_budget(deadline, addresses.len() - index) else {
            last = "Request timeout exhausted before the proxy connection".into();
            break;
        };
        match connect_tcp(*address, slice).await {
            Ok(stream) => return Ok(stream),
            Err(message) => last = message,
        }
    }
    Err(last)
}

async fn connect_tcp(address: SocketAddr, budget: std::time::Duration) -> Result<TcpStream, String> {
    let stream = tokio::time::timeout(budget, TcpStream::connect(address))
        .await
        .map_err(|_| format!("Connection to {address} timed out"))?
        .map_err(|err| format!("Connection to {address} failed: {err}"))?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

async fn resolve_target(
    host: &str,
    port: u16,
    settings: &Settings,
    deadline: Instant,
) -> Result<(Vec<SocketAddr>, f64), String> {
    let key = (host.to_ascii_lowercase(), port);
    if let Some(ip) = settings.resolve.get(&key) {
        ensure_family(*ip, settings.family)?;
        return Ok((vec![SocketAddr::new(*ip, port)], 0.0));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        ensure_family(ip, settings.family)?;
        return Ok((vec![SocketAddr::new(ip, port)], 0.0));
    }
    let wire = dns::wire_host(host)?;
    let lookup = dns::lookup(&wire, port, settings.family, budget(deadline)?).await?;
    Ok((lookup.addresses, lookup.dns_ms))
}

fn ensure_family(ip: IpAddr, family: Family) -> Result<(), String> {
    let ok = match family {
        Family::Any => true,
        Family::V4 => ip.is_ipv4(),
        Family::V6 => ip.is_ipv6(),
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "Resolved address {ip} does not match the requested IP family"
        ))
    }
}

fn plain_session(io: Io, dns_ms: f64, connect_ms: f64, ip: Option<IpAddr>) -> Session {
    Session {
        io,
        dns_ms,
        connect_ms,
        tls_ms: 0.0,
        ip,
        family: ip.map(|ip| family_label(ip).into()),
        tls: TlsMeta::default(),
        http2: false,
        absolute_form: false,
        proxy_authorization: None,
    }
}

async fn probe_certificate(address: SocketAddr, host: &str, deadline: Instant) -> TlsMeta {
    let budget = budget(deadline)
        .unwrap_or_default()
        .min(crate::exit::TLS_PROBE_MAX);
    if budget.is_zero() {
        return TlsMeta::default();
    }
    let Ok(stream) = connect_tcp(address, budget).await else {
        return TlsMeta::default();
    };
    let Ok(config) = tls::client_config(&Verify::Insecure, false) else {
        return TlsMeta::default();
    };
    let probe_deadline = Instant::now() + budget;
    match tls::budgeted_handshake(Box::new(stream), host, config, probe_deadline).await {
        Ok(tls) => tls.meta,
        Err(_) => TlsMeta::default(),
    }
}

async fn http_connect(
    io: &mut Io,
    authority: &str,
    authorization: Option<&str>,
    deadline: Instant,
) -> Result<(), String> {
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
    );
    if let Some(authorization) = authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    let slice = budget(deadline)?;
    tokio::time::timeout(slice, io.write_all(request.as_bytes()))
        .await
        .map_err(|_| "Proxy CONNECT timed out".to_string())?
        .map_err(|err| format!("Proxy CONNECT failed: {err}"))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let started = Instant::now();
    loop {
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16_384 {
            return Err("Proxy response headers are too large".into());
        }
        let left = slice.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err("Proxy CONNECT timed out".into());
        }
        let read = tokio::time::timeout(left, io.read(&mut tmp))
            .await
            .map_err(|_| "Proxy CONNECT timed out".to_string())?
            .map_err(|err| format!("Proxy CONNECT failed: {err}"))?;
        if read == 0 {
            return Err("Proxy closed the connection during CONNECT".into());
        }
        buf.extend_from_slice(&tmp[..read]);
    }
    let text = String::from_utf8_lossy(&buf);
    let status = text.lines().next().unwrap_or("");
    let code = status.split_whitespace().nth(1).unwrap_or("");
    if code == "200" {
        Ok(())
    } else {
        Err(format!("Proxy CONNECT failed: {status}"))
    }
}

fn connect_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn build_request(
    url: &Url,
    method: Method,
    body: Option<&[u8]>,
    headers: &[(String, String)],
    absolute_form: bool,
    proxy_authorization: Option<&str>,
) -> Request<Full<Bytes>> {
    let uri = if absolute_form {
        absolute_uri(url)
    } else if method_wants_absolute(url, absolute_form) {
        absolute_uri(url)
    } else {
        origin_form(url)
    };
    let mut builder = Request::builder().method(method.as_str()).uri(uri);
    let mut has_host = false;
    let mut has_user_agent = false;
    let mut has_accept = false;
    let mut has_authorization = false;
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        has_host |= lower == "host";
        has_user_agent |= lower == "user-agent";
        has_accept |= lower == "accept";
        has_authorization |= lower == "authorization";
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            builder = builder.header(name, value);
        }
    }
    if !has_host {
        if let Ok(value) = HeaderValue::from_str(&host_header(url)) {
            builder = builder.header(http::header::HOST, value);
        }
    }
    if !has_user_agent {
        builder = builder.header(http::header::USER_AGENT, user_agent());
    }
    if !has_accept {
        builder = builder.header(http::header::ACCEPT, "*/*");
    }
    if !has_authorization {
        if let Some(value) = url_basic_auth(url) {
            if let Ok(value) = HeaderValue::from_str(&value) {
                builder = builder.header(http::header::AUTHORIZATION, value);
            }
        }
    }
    if let Some(authorization) = proxy_authorization {
        if let Ok(value) = HeaderValue::from_str(authorization) {
            builder = builder.header(http::header::PROXY_AUTHORIZATION, value);
        }
    }
    let bytes = Bytes::from(body.unwrap_or_default().to_vec());
    builder
        .body(Full::new(bytes))
        .unwrap_or_else(|_| {
            Request::builder()
                .body(Full::new(Bytes::new()))
                .expect("empty request")
        })
}

fn method_wants_absolute(_url: &Url, _absolute: bool) -> bool {
    false
}

fn origin_form(url: &Url) -> String {
    let path = if url.path().is_empty() { "/" } else { url.path() };
    match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    }
}

fn absolute_uri(url: &Url) -> String {
    let host = host_header(url);
    let path = origin_form(url);
    format!("{}://{host}{path}", url.scheme())
}

fn host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let port = url.port_or_known_default().unwrap_or(80);
    let default = if url.scheme() == "https" { 443 } else { 80 };
    if port == default {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn url_basic_auth(url: &Url) -> Option<String> {
    if url.username().is_empty() {
        return None;
    }
    Some(basic_auth(url.username(), url.password().unwrap_or("")))
}

fn proxy_basic_auth(url: &Url) -> Option<String> {
    if url.username().is_empty() {
        return None;
    }
    Some(basic_auth(url.username(), url.password().unwrap_or("")))
}

fn proxy_user(url: &Url) -> Option<(String, String)> {
    if url.username().is_empty() {
        return None;
    }
    Some((
        percent_decode(url.username()),
        percent_decode(url.password().unwrap_or("")),
    ))
}

fn basic_auth(user: &str, password: &str) -> String {
    let raw = format!("{}:{}", percent_decode(user), percent_decode(password));
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

async fn dispatch(
    io: Io,
    request: Request<Full<Bytes>>,
    http2: bool,
    method: Method,
    deadline: Instant,
) -> Result<RawResponse, String> {
    let io = TokioIo::new(io);
    if http2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(io)
                .await
                .map_err(|err| format!("HTTP/2 connection failed: {err}"))?;
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let result = send_timed(&mut sender, request, method, deadline).await;
        drop(sender);
        task.abort();
        result
    } else {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|err| format!("HTTP/1.1 connection failed: {err}"))?;
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let result = send_timed(&mut sender, request, method, deadline).await;
        drop(sender);
        task.abort();
        result
    }
}

async fn send_timed(
    sender: &mut impl HttpSender,
    request: Request<Full<Bytes>>,
    method: Method,
    deadline: Instant,
) -> Result<RawResponse, String> {
    let slice = budget(deadline)?;
    let response = tokio::time::timeout(slice, sender.dispatch(request))
        .await
        .map_err(|_| "Request timed out".to_string())?
        .map_err(|err| format!("HTTP request failed: {err}"))?;
    collect_response(response, method, deadline).await
}

trait HttpSender {
    fn dispatch(
        &mut self,
        request: Request<Full<Bytes>>,
    ) -> impl std::future::Future<Output = Result<Response<Incoming>, hyper::Error>> + Send;
}

impl HttpSender for hyper::client::conn::http1::SendRequest<Full<Bytes>> {
    fn dispatch(
        &mut self,
        request: Request<Full<Bytes>>,
    ) -> impl std::future::Future<Output = Result<Response<Incoming>, hyper::Error>> + Send {
        self.send_request(request)
    }
}

impl HttpSender for hyper::client::conn::http2::SendRequest<Full<Bytes>> {
    fn dispatch(
        &mut self,
        request: Request<Full<Bytes>>,
    ) -> impl std::future::Future<Output = Result<Response<Incoming>, hyper::Error>> + Send {
        self.send_request(request)
    }
}

async fn collect_response(
    response: Response<Incoming>,
    method: Method,
    deadline: Instant,
) -> Result<RawResponse, String> {
    let ttfb = Instant::now();
    let status = response.status().as_u16();
    let version = response.version();
    let headers = response.headers().clone();
    let body = if method == Method::Head {
        Bytes::new()
    } else {
        let slice = budget(deadline)?;
        let collected = tokio::time::timeout(slice, response.into_body().collect())
            .await
            .map_err(|_| "Response body timed out".to_string())?
            .map_err(|err| format!("Response body failed: {err}"))?;
        collected.to_bytes()
    };
    Ok(RawResponse {
        status,
        version,
        headers,
        body,
        ttfb,
        end: Instant::now(),
    })
}

fn response_info(response: &RawResponse, method: Method) -> ResponseInfo {
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, value) in response.headers.iter() {
        let text = String::from_utf8_lossy(value.as_bytes()).into_owned();
        if let Some(existing) = headers
            .iter_mut()
            .find(|entry| entry.0.eq_ignore_ascii_case(name.as_str()))
        {
            existing.1.push_str(", ");
            existing.1.push_str(&text);
        } else {
            headers.push((name.as_str().to_string(), text));
        }
    }
    let content_type = header_get(&headers, "content-type");
    let server = header_get(&headers, "server");
    let location = header_get(&headers, "location");
    let date = header_get(&headers, "date").and_then(|value| parse_http_date(&value));
    let headers = sanitize_headers(&headers);
    ResponseInfo {
        status: Some(response.status),
        bytes: if method == Method::Head {
            0
        } else {
            response.body.len() as u64
        },
        content_type,
        server,
        date,
        location,
        headers,
    }
}

fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

fn parse_http_date(value: &str) -> Option<String> {
    let time = httpdate::parse_http_date(value).ok()?;
    let secs = time
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(tls::unix_to_iso(secs))
}

fn version_name(version: Version) -> String {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
    .to_string()
}

fn apply_tls(network: &mut NetworkInfo, tls: &TlsMeta) {
    if tls.version.is_some() {
        network.tls_version = tls.version.clone();
    }
    if tls.cipher.is_some() {
        network.tls_cipher = tls.cipher.clone();
    }
    if tls.cert_cn.is_some() {
        network.cert_cn = tls.cert_cn.clone();
    }
    if tls.cert_days_left.is_some() {
        network.cert_days_left = tls.cert_days_left;
    }
    if !tls.cert_sans.is_empty() {
        network.cert_sans = tls.cert_sans.clone();
    }
    if tls.cert_issuer.is_some() {
        network.cert_issuer = tls.cert_issuer.clone();
    }
    if tls.cert_serial.is_some() {
        network.cert_serial = tls.cert_serial.clone();
    }
    if tls.cert_not_before.is_some() {
        network.cert_not_before = tls.cert_not_before.clone();
    }
    if tls.cert_not_after.is_some() {
        network.cert_not_after = tls.cert_not_after.clone();
    }
}

fn budget(deadline: Instant) -> Result<std::time::Duration, String> {
    let now = Instant::now();
    if now >= deadline {
        Err("Request timeout exhausted".into())
    } else {
        Ok(deadline.saturating_duration_since(now))
    }
}

fn slice_budget(deadline: Instant, parts: usize) -> Result<std::time::Duration, String> {
    let total = budget(deadline)?;
    let parts = u32::try_from(parts.max(1)).unwrap_or(1);
    Ok((total / parts).max(std::time::Duration::from_millis(1)))
}

fn fail(
    message: String,
    network: NetworkInfo,
    response: Option<ResponseInfo>,
    timing: TimingMetrics,
) -> Result<Outcome, RequestError> {
    Err(RequestError {
        message,
        network,
        response,
        timing,
        kind: "network",
    })
}

fn dial_err(message: String) -> DialError {
    DialError {
        message,
        ip: None,
        family: None,
        dns_ms: 0.0,
        connect_ms: 0.0,
        tls_ms: 0.0,
        tls: TlsMeta::default(),
    }
}
