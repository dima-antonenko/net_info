use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use url::Url;

use crate::client;
use crate::models::{Method, StepMetrics};
use crate::options::Settings;

pub async fn export(endpoint: &str, steps: &[StepMetrics], timeout: std::time::Duration) -> Result<(), String> {
    let url = traces_url(endpoint)?;
    let body = serde_json::to_vec(&document(steps)).map_err(|err| err.to_string())?;
    let parsed = Url::parse(&url).map_err(|err| format!("Invalid OTLP endpoint: {err}"))?;
    let settings = Settings {
        timeout,
        http2: false,
        ..Settings::default()
    };
    let deadline = std::time::Instant::now() + timeout;
    let outcome = client::perform(
        &parsed,
        Method::Post,
        Some(&body),
        &[
            ("Content-Type".into(), "application/json".into()),
            ("User-Agent".into(), crate::exit::user_agent()),
        ],
        deadline,
        &settings,
    )
    .await
    .map_err(|err| format!("OTLP export failed: {}", err.message))?;
    let status = outcome.response.status.unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(format!("OTLP export failed: HTTP {status}"));
    }
    Ok(())
}

fn traces_url(endpoint: &str) -> Result<String, String> {
    let trimmed = endpoint.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("OTLP endpoint is empty".into());
    }
    if trimmed.ends_with("/v1/traces") {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("{trimmed}/v1/traces"))
    }
}

fn document(steps: &[StepMetrics]) -> Value {
    let end = now_ns();
    let total: u128 = steps
        .iter()
        .map(|step| (step.timing.total_ms.max(0.0) * 1_000_000.0) as u128)
        .sum();
    let mut cursor = end.saturating_sub(total);
    let root_id = random_hex(8);
    let trace_id = random_hex(16);
    let mut spans = vec![span(
        &trace_id,
        &root_id,
        None,
        "net-info.analysis",
        cursor,
        end,
        vec![attr_int("net_info.steps", steps.len() as i64)],
    )];
    for step in steps {
        let step_end = cursor.saturating_add((step.timing.total_ms.max(0.0) * 1_000_000.0) as u128);
        let step_id = random_hex(8);
        let mut attributes = vec![
            attr_int("net_info.step_number", step.step_number as i64),
            attr_int("http.response.body.size", step.response.bytes as i64),
        ];
        if let Some(method) = &step.request_method {
            attributes.push(attr_str("http.request.method", method));
        }
        if let Some(status) = step.response.status {
            attributes.push(attr_int("http.response.status_code", status as i64));
        }
        if let Some(host) = url::Url::parse(&step.url).ok().and_then(|url| url.host_str().map(str::to_string)) {
            attributes.push(attr_str("server.address", &host));
        }
        if let Some(ip) = &step.network.ip {
            attributes.push(attr_str("network.peer.address", ip));
        }
        if let Some(version) = &step.network.http_version {
            attributes.push(attr_str("network.protocol.version", version));
        }
        if let Some(version) = &step.network.tls_version {
            attributes.push(attr_str("tls.protocol.version", version));
        }
        spans.push(span(
            &trace_id,
            &step_id,
            Some(&root_id),
            "http.request",
            cursor,
            step_end,
            attributes,
        ));
        let mut phase_cursor = cursor;
        for phase in ["dns", "connect", "tls", "wait", "xfer"] {
            let duration = step.timing.phase(phase).unwrap_or(0.0).max(0.0);
            let phase_end = phase_cursor.saturating_add((duration * 1_000_000.0) as u128).min(step_end);
            spans.push(span(
                &trace_id,
                &random_hex(8),
                Some(&step_id),
                &format!("http.{phase}"),
                phase_cursor,
                phase_end,
                vec![
                    attr_str("net_info.phase", phase),
                    attr_double("net_info.duration_ms", duration),
                ],
            ));
            phase_cursor = phase_end;
        }
        cursor = step_end;
    }
    json!({
        "resourceSpans": [{
            "resource": {"attributes": [attr_str("service.name", "net-info")]},
            "scopeSpans": [{
                "scope": {"name": "net-info"},
                "spans": spans
            }]
        }]
    })
}

fn span(
    trace_id: &str,
    span_id: &str,
    parent: Option<&str>,
    name: &str,
    start: u128,
    end: u128,
    attributes: Vec<Value>,
) -> Value {
    let mut value = json!({
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "startTimeUnixNano": start.to_string(),
        "endTimeUnixNano": end.to_string(),
        "attributes": attributes,
    });
    if let Some(parent) = parent {
        value["parentSpanId"] = json!(parent);
    }
    value
}

fn attr_str(key: &str, value: &str) -> Value {
    json!({"key": key, "value": {"stringValue": value}})
}

fn attr_int(key: &str, value: i64) -> Value {
    json!({"key": key, "value": {"intValue": value.to_string()}})
}

fn attr_double(key: &str, value: f64) -> Value {
    json!({"key": key, "value": {"doubleValue": value}})
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = file.read(&mut buf);
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes * 2);
    for byte in buf {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
