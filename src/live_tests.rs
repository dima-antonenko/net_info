use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::cli::run_from;
use crate::exit::{EXIT_HTTP, EXIT_OK, EXIT_REDIRECTS, EXIT_SLO, EXIT_USAGE};

fn respond(status: u16, extra: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
        body.len()
    )
}

fn request_path(request: &str) -> String {
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string()
}

fn spawn_http<F>(handler: F) -> u16
where
    F: Fn(&str) -> String + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for _ in 0..16 {
            let Ok((mut socket, _)) = listener.accept() else {
                break;
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .ok();
            let mut buf = [0u8; 8192];
            let size = socket.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..size]);
            let response = handler(&request);
            let _ = socket.write_all(response.as_bytes());
        }
    });
    port
}

fn clean_env() -> HashMap<String, String> {
    HashMap::new()
}

#[tokio::test]
async fn http_get_reports_phases_and_status() {
    let port = spawn_http(|request| {
        let path = request_path(request);
        respond(200, "Content-Type: text/plain\r\nServer: live\r\n", &path)
    });
    let dir = std::env::temp_dir().join(format!("net-info-{port}.json"));
    let code = run_from(
        vec![
            format!("http://127.0.0.1:{port}/hello"),
            "--metrics-only".into(),
            "--json".into(),
            dir.display().to_string(),
            "--no-http2".into(),
        ],
        clean_env(),
    )
    .await;
    assert_eq!(code, EXIT_OK);
    let report = std::fs::read_to_string(&dir).unwrap();
    assert!(report.contains("\"status\": 200"), "{report}");
    assert!(report.contains("\"http_version\": \"HTTP/1.1\""), "{report}");
    assert!(report.contains("hello"), "{report}");
    let value: serde_json::Value = serde_json::from_str(&report).unwrap();
    let timing = &value["steps"][0]["timing"];
    assert!(timing["total_ms"].as_f64().unwrap() >= timing["ttfb_ms"].as_f64().unwrap());
    assert!(timing["connect_ms"].as_f64().unwrap() >= 0.0);
    let _ = std::fs::remove_file(dir);
}

#[tokio::test]
async fn follows_redirects_and_masks_secrets() {
    let port = spawn_http(|request| {
        let path = request_path(request);
        if path.starts_with("/start") {
            respond(302, "Location: /done\r\n", "")
        } else {
            respond(200, "Content-Type: text/plain\r\n", "done")
        }
    });
    let json_path = std::env::temp_dir().join(format!("net-info-mask-{port}.json"));
    let code = run_from(
        vec![
            format!("http://user:secret@127.0.0.1:{port}/start"),
            "--follow".into(),
            "--metrics-only".into(),
            "-H".into(),
            "Authorization: Bearer supersecret".into(),
            "--json".into(),
            json_path.display().to_string(),
            "--no-http2".into(),
        ],
        clean_env(),
    )
    .await;
    assert_eq!(code, EXIT_OK);
    let report = std::fs::read_to_string(&json_path).unwrap();
    let _ = std::fs::remove_file(&json_path);
    assert!(!report.contains("secret"), "{report}");
    assert!(report.contains("****"), "{report}");
}

#[tokio::test]
async fn fail_slo_and_redirect_limit_have_distinct_codes() {
    let port = spawn_http(|_| respond(500, "", "nope"));
    let code = run_from(
        vec![
            format!("http://127.0.0.1:{port}/"),
            "--fail".into(),
            "--metrics-only".into(),
            "--no-http2".into(),
        ],
        clean_env(),
    )
    .await;
    assert_eq!(code, EXIT_HTTP);

    let code = run_from(
        vec![
            format!("http://127.0.0.1:{port}/"),
            "--slo".into(),
            "total=0.001".into(),
            "--metrics-only".into(),
            "--no-http2".into(),
        ],
        clean_env(),
    )
    .await;
    assert_eq!(code, EXIT_SLO);

    let loop_port = spawn_http(|_| respond(302, "Location: /again\r\n", ""));
    let code = run_from(
        vec![
            format!("http://127.0.0.1:{loop_port}/again"),
            "--follow".into(),
            "--metrics-only".into(),
            "--no-http2".into(),
        ],
        clean_env(),
    )
    .await;
    assert_eq!(code, EXIT_REDIRECTS);
}

#[tokio::test]
async fn rejects_invalid_input() {
    assert_eq!(
        run_from(vec!["ftp://example.com".into()], clean_env()).await,
        EXIT_USAGE
    );
    assert_eq!(
        run_from(
            vec!["http://example.com".into(), "--slo".into(), "nope=1".into()],
            clean_env()
        )
        .await,
        EXIT_USAGE
    );
}

#[tokio::test]
async fn http_proxy_and_socks_reach_origin() {
    let origin = spawn_http(|_| respond(200, "Content-Type: text/plain\r\n", "proxied"));
    let proxy = spawn_absolute_proxy();
    let code = run_from(
        vec![
            format!("http://127.0.0.1:{origin}/via-proxy"),
            "--proxy".into(),
            format!("http://127.0.0.1:{proxy}"),
            "--metrics-only".into(),
            "--no-http2".into(),
        ],
        clean_env(),
    )
    .await;
    assert_eq!(code, EXIT_OK);

    let socks = spawn_socks();
    let code = run_from(
        vec![
            format!("http://127.0.0.1:{origin}/via-socks"),
            "--proxy".into(),
            format!("socks5://127.0.0.1:{socks}"),
            "--metrics-only".into(),
            "--no-http2".into(),
        ],
        clean_env(),
    )
    .await;
    assert_eq!(code, EXIT_OK);
}

#[tokio::test]
async fn tls_insecure_and_custom_ca() {
    let (port, ca_pem) = spawn_tls();
    let insecure = run_from(
        vec![
            format!("https://localhost:{port}/tls"),
            "--resolve".into(),
            format!("localhost:{port}:127.0.0.1"),
            "--insecure".into(),
            "--metrics-only".into(),
        ],
        clean_env(),
    )
    .await;
    assert_eq!(insecure, EXIT_OK);

    let ca_path = std::env::temp_dir().join(format!("net-info-{port}.pem"));
    std::fs::write(&ca_path, ca_pem).unwrap();
    let trusted = run_from(
        vec![
            format!("https://localhost:{port}/tls"),
            "--resolve".into(),
            format!("localhost:{port}:127.0.0.1"),
            "--cacert".into(),
            ca_path.display().to_string(),
            "--metrics-only".into(),
            "--har".into(),
            std::env::temp_dir()
                .join(format!("net-info-{port}.har"))
                .display()
                .to_string(),
        ],
        clean_env(),
    )
    .await;
    assert_eq!(trusted, EXIT_OK);
    let _ = std::fs::remove_file(ca_path);
}

fn spawn_absolute_proxy() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((mut client, _)) = listener.accept() else {
            return;
        };
        client.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let mut buf = vec![0u8; 8192];
        let size = client.read(&mut buf).unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..size]).to_string();
        let line = request.lines().next().unwrap_or("");
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("GET");
        let target = parts.next().unwrap_or("/");
        let version = parts.next().unwrap_or("HTTP/1.1");
        let parsed = url::Url::parse(target).ok();
        let path = parsed
            .as_ref()
            .map(|url| {
                let mut path = url.path().to_string();
                if let Some(query) = url.query() {
                    path.push('?');
                    path.push_str(query);
                }
                if path.is_empty() { "/".into() } else { path }
            })
            .unwrap_or_else(|| "/".into());
        let upstream_addr = parsed
            .as_ref()
            .and_then(|url| {
                let host = url.host_str()?;
                let port = url.port_or_known_default()?;
                Some(format!("{host}:{port}"))
            })
            .unwrap_or_else(|| "127.0.0.1:1".into());
        let rest = request.split_once("\r\n").map(|(_, rest)| rest).unwrap_or("");
        let forwarded = format!("{method} {path} {version}\r\n{rest}");
        if let Ok(mut upstream) = TcpStream::connect(upstream_addr) {
            upstream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .ok();
            let _ = upstream.write_all(forwarded.as_bytes());
            let mut response = Vec::new();
            let _ = upstream.read_to_end(&mut response);
            let _ = client.write_all(&response);
        }
    });
    port
}

fn spawn_socks() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((mut client, _)) = listener.accept() else {
            return;
        };
        client.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let mut greeting = [0u8; 2];
        if client.read_exact(&mut greeting).is_err() {
            return;
        }
        let mut methods = vec![0u8; greeting[1] as usize];
        if client.read_exact(&mut methods).is_err() {
            return;
        }
        let _ = client.write_all(&[0x05, 0x00]);
        let mut head = [0u8; 4];
        if client.read_exact(&mut head).is_err() {
            return;
        }
        let target = match head[3] {
            0x01 => {
                let mut raw = [0u8; 6];
                if client.read_exact(&mut raw).is_err() {
                    return;
                }
                let ip = IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]));
                let port = u16::from_be_bytes([raw[4], raw[5]]);
                SocketAddr::new(ip, port)
            }
            0x03 => {
                let mut len = [0u8; 1];
                if client.read_exact(&mut len).is_err() {
                    return;
                }
                let mut host = vec![0u8; len[0] as usize];
                if client.read_exact(&mut host).is_err() {
                    return;
                }
                let mut port_raw = [0u8; 2];
                if client.read_exact(&mut port_raw).is_err() {
                    return;
                }
                let host = String::from_utf8_lossy(&host);
                let port = u16::from_be_bytes(port_raw);
                match format!("{host}:{port}").parse() {
                    Ok(addr) => addr,
                    Err(_) => return,
                }
            }
            _ => return,
        };
        let _ = client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        if let Ok(mut upstream) = TcpStream::connect(target) {
            upstream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .ok();
            let mut from_client = client.try_clone().unwrap();
            let mut to_upstream = upstream.try_clone().unwrap();
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut from_client, &mut to_upstream);
            });
            let _ = std::io::copy(&mut upstream, &mut client);
        }
    });
    port
}

fn spawn_tls() -> (u16, String) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use rustls::ServerConfig;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    crate::tls::ensure_crypto();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec!["Test CA".into()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca.pem();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    let certs = vec![leaf.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server = std::sync::Arc::new(server);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for _ in 0..4 {
            let Ok((mut tcp, _)) = listener.accept() else {
                break;
            };
            tcp.set_read_timeout(Some(Duration::from_secs(3))).ok();
            let Ok(mut connection) = rustls::ServerConnection::new(server.clone()) else {
                continue;
            };
            let mut tls = rustls::Stream::new(&mut connection, &mut tcp);
            let mut buf = [0u8; 4096];
            let _ = tls.read(&mut buf);
            let body = "secure";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = tls.write_all(response.as_bytes());
        }
    });
    (port, ca_pem)
}
