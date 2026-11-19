use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

#[test]
fn binary_prints_metrics_for_a_local_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .ok();
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf);
        let body = "ok";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes());
    });

    let output = Command::new(env!("CARGO_BIN_EXE_net-info"))
        .args([
            "--metrics-only",
            "--no-http2",
            &format!("http://127.0.0.1:{port}/"),
        ])
        .env_remove("http_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("all_proxy")
        .env_remove("ALL_PROXY")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout={stdout}\nstderr={stderr}"
    );
    assert!(stdout.contains("status=200"), "{stdout}");
    assert!(stdout.contains("bytes=2"), "{stdout}");
}
