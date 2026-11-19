use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::exit::VERSION;
use crate::models::StepMetrics;
use crate::slo::SloResult;
use crate::tls::unix_to_iso;

pub fn write_json(
    steps: &[StepMetrics],
    initial_url: &str,
    path: &str,
    slo: Option<&SloResult>,
) -> Result<(), String> {
    let payload = json_report(steps, initial_url, slo);
    let text = serde_json::to_string_pretty(&payload).map_err(|err| err.to_string())?;
    write_output(path, &format!("{text}\n"))
}

pub fn json_report(steps: &[StepMetrics], initial_url: &str, slo: Option<&SloResult>) -> Value {
    let successful: Vec<_> = steps.iter().filter(|step| !step.has_error()).collect();
    let mut summary = json!({
        "total_time_ms": successful.iter().map(|step| step.timing.total_ms).sum::<f64>(),
        "final_status": steps.last().filter(|step| !step.has_error()).and_then(|step| step.response.status),
        "final_url": steps.last().map(|step| step.url.as_str()).unwrap_or(initial_url),
        "final_bytes": steps.last().filter(|step| !step.has_error()).map(|step| step.response.bytes).unwrap_or(0),
        "errors": steps.iter().filter(|step| step.has_error() || step.redirect_limit_reached).count(),
    });
    if let Some(slo) = slo {
        summary["slo"] = slo.to_json();
    }
    json!({
        "schema_version": 1,
        "net_info_version": VERSION,
        "timestamp": unix_to_iso(now_secs()),
        "initial_url": initial_url,
        "total_steps": steps.len(),
        "steps": steps.iter().map(StepMetrics::to_json).collect::<Vec<_>>(),
        "summary": summary,
    })
}

pub fn write_har(steps: &[StepMetrics], initial_url: &str, path: &str) -> Result<(), String> {
    let text = serde_json::to_string_pretty(&har_document(steps, initial_url))
        .map_err(|err| err.to_string())?;
    write_output(path, &format!("{text}\n"))
}

pub fn har_document(steps: &[StepMetrics], initial_url: &str) -> Value {
    let timings: Vec<Value> = steps.iter().map(har_timings).collect();
    let durations: Vec<f64> = timings.iter().map(har_entry_time).collect();
    let total_ns: i128 = durations.iter().map(|ms| (*ms * 1_000_000.0).round() as i128).sum();
    let end_ns = now_ns();
    let mut cursor = end_ns - total_ns;
    let mut entries = Vec::new();
    for ((step, timing), duration) in steps.iter().zip(timings.iter()).zip(durations.iter()) {
        entries.push(har_entry(step, timing, *duration, cursor));
        cursor += (*duration * 1_000_000.0).round() as i128;
    }
    json!({
        "log": {
            "version": "1.2",
            "creator": {"name": "net-info", "version": VERSION},
            "pages": [{
                "startedDateTime": iso_from_ns(end_ns - total_ns),
                "id": "page_1",
                "title": initial_url,
                "pageTimings": {"onContentLoad": -1, "onLoad": -1}
            }],
            "entries": entries
        }
    })
}

fn har_entry(step: &StepMetrics, timings: &Value, duration: f64, start_ns: i128) -> Value {
    let mut entry = json!({
        "pageref": "page_1",
        "startedDateTime": iso_from_ns(start_ns),
        "time": duration,
        "request": {
            "method": step.request_method.as_deref().unwrap_or("GET"),
            "url": step.url,
            "httpVersion": step.network.http_version.as_deref().unwrap_or(""),
            "cookies": [],
            "headers": name_values(&step.request_headers),
            "queryString": query_pairs(&step.url),
            "headersSize": -1,
            "bodySize": step.request_body_bytes,
        },
        "response": har_response(step),
        "cache": {},
        "timings": timings,
    });
    if let Some(ip) = &step.network.ip {
        entry["serverIPAddress"] = json!(ip);
    }
    if step.network.tls_version.is_some() {
        entry["_tls"] = json!({
            "version": step.network.tls_version,
            "cipher": step.network.tls_cipher,
            "certCN": step.network.cert_cn,
            "certIssuer": step.network.cert_issuer,
            "certDaysLeft": step.network.cert_days_left,
            "verified": step.network.tls_verified,
        });
    }
    if let Some(proxy) = &step.proxied_via {
        entry["_proxy"] = json!({"url": proxy, "source": step.network.proxy_source});
    }
    if step.redirect_limit_reached {
        entry["_redirectLimitReached"] = json!(true);
    }
    entry
}

fn har_response(step: &StepMetrics) -> Value {
    let received = step.response.status.is_some();
    let mut response = json!({
        "status": step.response.status.unwrap_or(0),
        "statusText": reason(step.response.status.unwrap_or(0)),
        "httpVersion": step.network.http_version.as_deref().unwrap_or(""),
        "cookies": [],
        "headers": name_values(&step.response.headers),
        "content": {
            "size": if received { step.response.bytes } else { 0 },
            "mimeType": step.response.content_type.as_deref().unwrap_or("x-unknown"),
        },
        "redirectURL": step.response.location.as_deref().unwrap_or(""),
        "headersSize": -1,
        "bodySize": if received { step.response.bytes as i64 } else { -1 },
        "_transferSize": if received { step.response.bytes as i64 } else { -1 },
    });
    if let Some(error) = &step.error {
        response["_error"] = json!(error);
        response["_errorKind"] = json!(step.error_kind);
    }
    response
}

fn har_timings(step: &StepMetrics) -> Value {
    if step.has_error() {
        return json!({
            "blocked": -1, "dns": -1, "connect": -1, "send": 0,
            "wait": 0, "receive": 0, "ssl": -1
        });
    }
    let mut timings = json!({
        "blocked": -1,
        "dns": round_ms(step.timing.dns_ms),
        "connect": round_ms(step.timing.connect_ms + step.timing.tls_ms),
        "send": 0,
        "wait": round_ms(step.timing.wait_ms),
        "receive": round_ms(step.timing.xfer_ms),
        "ssl": if step.url.to_ascii_lowercase().starts_with("https:") {
            round_ms(step.timing.tls_ms)
        } else {
            -1.0
        },
    });
    if step.timing.is_estimated {
        timings["_estimated"] = json!(true);
    }
    timings
}

fn har_entry_time(timings: &Value) -> f64 {
    ["blocked", "dns", "connect", "send", "wait", "receive"]
        .into_iter()
        .filter_map(|phase| timings.get(phase).and_then(Value::as_f64))
        .filter(|value| *value >= 0.0)
        .sum()
}

fn round_ms(value: f64) -> f64 {
    (value.max(0.0) * 1000.0).round() / 1000.0
}

fn name_values(headers: &[(String, String)]) -> Vec<Value> {
    headers
        .iter()
        .map(|(name, value)| json!({"name": name, "value": value}))
        .collect()
}

fn query_pairs(url: &str) -> Vec<Value> {
    let query = url.split_once('#').map(|(left, _)| left).unwrap_or(url);
    let Some(query) = query.split_once('?').map(|(_, query)| query) else {
        return Vec::new();
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            json!({"name": name, "value": value})
        })
        .collect()
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

pub fn write_prometheus(steps: &[StepMetrics], path: &str) -> Result<(), String> {
    write_output(path, &prometheus_text(steps, now_secs() as f64))
}

pub fn prometheus_text(steps: &[StepMetrics], now: f64) -> String {
    let mut lines = vec![
        "# HELP net_info_request_success Whether the request step completed without a network error.".into(),
        "# TYPE net_info_request_success gauge".into(),
        "# HELP net_info_request_duration_seconds HTTP request timing by phase.".into(),
        "# TYPE net_info_request_duration_seconds gauge".into(),
        "# HELP net_info_response_status_code HTTP response status code.".into(),
        "# TYPE net_info_response_status_code gauge".into(),
        "# HELP net_info_response_body_size_bytes HTTP response body size.".into(),
        "# TYPE net_info_response_body_size_bytes gauge".into(),
        "# HELP net_info_last_run_timestamp_seconds Unix time when net-info wrote this file.".into(),
        "# TYPE net_info_last_run_timestamp_seconds gauge".into(),
    ];
    for step in steps {
        let labels = format!(
            "host=\"{}\",step=\"{}\"",
            escape_label(&hostname(&step.url)),
            step.step_number
        );
        lines.push(format!(
            "net_info_request_success{{{labels}}} {}",
            if step.has_error() { 0 } else { 1 }
        ));
        if step.has_error() {
            continue;
        }
        for phase in ["dns", "connect", "tls", "ttfb", "wait", "xfer", "total"] {
            let value = step.timing.phase(phase).unwrap_or(0.0) / 1000.0;
            lines.push(format!(
                "net_info_request_duration_seconds{{{labels},phase=\"{phase}\"}} {value:.12}"
            ));
        }
        if let Some(status) = step.response.status {
            lines.push(format!("net_info_response_status_code{{{labels}}} {status}"));
        }
        lines.push(format!(
            "net_info_response_body_size_bytes{{{labels}}} {}",
            step.response.bytes
        ));
    }
    if let Some(step) = steps.first() {
        lines.push(format!(
            "net_info_last_run_timestamp_seconds{{host=\"{}\"}} {now:.3}",
            escape_label(&hostname(&step.url))
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn hostname(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_default()
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn write_output(path: &str, text: &str) -> Result<(), String> {
    if path == "-" {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(text.as_bytes())
            .map_err(|err| format!("Failed to write export: {err}"))?;
        return Ok(());
    }
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|err| format!("Failed to create {}: {err}", parent.display()))?;
        }
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, text).map_err(|err| format!("Failed to write {}: {err}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|err| format!("Failed to write {}: {err}", path.display()))?;
    Ok(())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn now_ns() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as i128)
        .unwrap_or(0)
}

fn iso_from_ns(ns: i128) -> String {
    unix_to_iso((ns / 1_000_000_000) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{NetworkInfo, ResponseInfo, TimingMetrics};

    #[test]
    fn prometheus_skips_timings_for_failures() {
        let step = StepMetrics {
            url: "http://example.com/health".into(),
            step_number: 1,
            error: Some("nope".into()),
            error_kind: Some("network".into()),
            timing: TimingMetrics::default(),
            network: NetworkInfo::default(),
            response: ResponseInfo::default(),
            note: None,
            proxied_via: None,
            request_method: Some("GET".into()),
            request_headers: Vec::new(),
            request_body_bytes: 0,
            redirect_limit_reached: false,
        };
        let text = prometheus_text(&[step], 10.0);
        assert!(text.contains("net_info_request_success{host=\"example.com\",step=\"1\"} 0"));
        assert!(!text.contains("phase=\"dns\""));
    }
}
