use crate::exit::{CERT_EXPIRY_CRITICAL_DAYS, CERT_EXPIRY_WARNING_DAYS};
use crate::models::StepMetrics;
use crate::proxy::{SOURCE_CLI, SOURCE_DISABLED, SOURCE_NO_MATCH, SOURCE_NO_PROXY};
use crate::redact::{format_bytes_human, format_metric_value};
use crate::slo::{SloResult, select_step_for_evaluation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Rich,
    Compact,
    Metrics,
}

pub struct View {
    pub mode: Mode,
    pub color: bool,
    pub initial_url: String,
    pub slo: Option<SloResult>,
}

pub fn render(steps: &[StepMetrics], view: &View) -> String {
    match view.mode {
        Mode::Metrics => metrics(steps, view.slo.as_ref()),
        Mode::Compact => {
            let mut out = header(&view.initial_url, view.color);
            for step in steps {
                if step.has_error() {
                    out.push_str(&format!(
                        "Step {}: ERROR - {}\n",
                        step.step_number,
                        step.error.as_deref().unwrap_or("request failed")
                    ));
                } else {
                    out.push_str(&compact_line(step));
                    out.push('\n');
                }
            }
            if steps.len() > 1 {
                out.push_str(&redirect_summary(steps, view.color));
            }
            if let Some(slo) = &view.slo {
                out.push_str(&slo_panel(slo, view.color));
            }
            out
        }
        Mode::Rich => rich(steps, view),
    }
}

fn rich(steps: &[StepMetrics], view: &View) -> String {
    let mut out = header(&view.initial_url, view.color);
    for step in steps {
        out.push_str(&panel(
            &format!("Step {}: {}", step.step_number, step.url),
            view.color,
            "36",
        ));
        if step.has_error() {
            out.push_str(&panel(
                &format!(
                    "Error: {}",
                    step.error.as_deref().unwrap_or("request failed")
                ),
                view.color,
                "31",
            ));
            if let Some(line) = network_line(step, view.color) {
                out.push_str(&line);
                out.push('\n');
            }
            continue;
        }
        if let Some(line) = network_line(step, view.color) {
            out.push_str(&line);
            out.push('\n');
        }
        if let Some(line) = response_line(step, view.color) {
            out.push_str(&line);
            out.push('\n');
        }
        out.push_str(&waterfall(step, view.color));
        out.push('\n');
    }
    if steps.len() > 1 {
        out.push_str(&redirect_summary(steps, view.color));
    }
    if let Some(slo) = &view.slo {
        out.push_str(&slo_panel(slo, view.color));
    }
    out
}

fn metrics(steps: &[StepMetrics], slo: Option<&SloResult>) -> String {
    let target = slo.and_then(|_| select_step_for_evaluation(steps).map(|step| step.step_number));
    let mut out = String::new();
    for step in steps {
        if step.has_error() {
            let mut parts = vec![format!(
                "Step {}: ERROR - {}",
                step.step_number,
                step.error.as_deref().unwrap_or("request failed")
            )];
            for (key, value) in [
                ("cert_cn", step.network.cert_cn.clone()),
                (
                    "cert_sans",
                    (!step.network.cert_sans.is_empty()).then(|| step.network.cert_sans.join(",")),
                ),
                ("cert_issuer", step.network.cert_issuer.clone()),
                ("cert_not_before", step.network.cert_not_before.clone()),
                ("cert_not_after", step.network.cert_not_after.clone()),
                (
                    "cert_days_left",
                    step.network.cert_days_left.map(|days| days.to_string()),
                ),
            ] {
                if let Some(value) = value.filter(|value| !value.is_empty()) {
                    parts.push(format!("{key}={}", format_metric_value(&value)));
                }
            }
            out.push_str(&parts.join(" "));
            out.push('\n');
            continue;
        }
        let mut parts = vec![
            format!("dns={:.1}", step.timing.dns_ms),
            format!("connect={:.1}", step.timing.connect_ms),
            format!("tls={:.1}", step.timing.tls_ms),
            format!("ttfb={:.1}", step.timing.ttfb_ms),
            format!("total={:.1}", step.timing.total_ms),
            format!("status={}", step.response.status.unwrap_or(0)),
            format!("bytes={}", step.response.bytes),
        ];
        if let Some(ip) = &step.network.ip {
            parts.push(format!("ip={}", format_metric_value(ip)));
        }
        if let Some(family) = &step.network.ip_family {
            parts.push(format!("family={}", format_metric_value(family)));
        }
        if let Some(version) = &step.network.tls_version {
            parts.push(format!("tls_version={}", format_metric_value(version)));
        }
        parts.push(proxy_metric(step));
        if slo.is_some() && Some(step.step_number) == target {
            if slo.is_some_and(|result| result.passed()) {
                parts.push("slo=pass".into());
            } else if let Some(result) = slo {
                let keys = result
                    .violations
                    .iter()
                    .map(|violation| violation.key.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                parts.push("slo=fail".into());
                parts.push(format!("slo_violations={keys}"));
            }
        }
        out.push_str(&format!("Step {}: {}\n", step.step_number, parts.join(" ")));
    }
    out
}

fn proxy_metric(step: &StepMetrics) -> String {
    if let Some(proxy) = &step.proxied_via {
        let hint = if step.network.proxy_source.as_deref() == Some(SOURCE_CLI) {
            "arg".into()
        } else {
            format!("env:{}", step.network.proxy_source.as_deref().unwrap_or(""))
        };
        return format!(
            "proxy={} proxy_from={}",
            format_metric_value(proxy),
            format_metric_value(&hint)
        );
    }
    match step.network.proxy_source.as_deref() {
        Some(SOURCE_NO_PROXY) => "proxy=none proxy_from=env:no_proxy".into(),
        Some(SOURCE_DISABLED) => "proxy=disabled proxy_from=arg".into(),
        Some(SOURCE_NO_MATCH) => "proxy=direct proxy_from=no_scheme_match".into(),
        _ => "proxy=direct".into(),
    }
}

fn compact_line(step: &StepMetrics) -> String {
    let status = step
        .response
        .status
        .map(|status| status.to_string())
        .unwrap_or_else(|| "—".into());
    format!(
        "Step {}: {status} {} {} | dns={:.1}ms connect={:.1}ms tls={:.1}ms ttfb={:.1}ms total={:.1}ms | {}",
        step.step_number,
        step.request_method.as_deref().unwrap_or("GET"),
        step.url,
        step.timing.dns_ms,
        step.timing.connect_ms,
        step.timing.tls_ms,
        step.timing.ttfb_ms,
        step.timing.total_ms,
        format_bytes_human(step.response.bytes)
    )
}

fn network_line(step: &StepMetrics, color: bool) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(ip) = &step.network.ip {
        if let Some(family) = &step.network.ip_family {
            parts.push(format!("IP: {ip} ({family})"));
        } else {
            parts.push(format!("IP: {ip}"));
        }
    }
    if let Some(version) = &step.network.http_version {
        parts.push(format!("HTTP: {version}"));
    }
    parts.push(proxy_text(step));
    for (label, value) in [
        ("TLS", step.network.tls_version.as_deref()),
        ("Cipher", step.network.tls_cipher.as_deref()),
        ("Cert", step.network.cert_cn.as_deref()),
        ("Issuer", step.network.cert_issuer.as_deref()),
    ] {
        if let Some(value) = value {
            parts.push(format!("{label}: {value}"));
        }
    }
    if let Some(days) = step.network.cert_days_left {
        let painted = paint(
            &format!("Expires: {days}d"),
            expiry_color(days),
            color,
        );
        parts.push(painted);
    }
    if step.network.tls_verified == Some(false) {
        parts.push(paint("TLS verification disabled", "31", color));
    } else if step.network.tls_custom_ca == Some(true) {
        parts.push("TLS CA: custom bundle".into());
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("  {}", parts.join(" | ")))
    }
}

fn proxy_text(step: &StepMetrics) -> String {
    let source = step.network.proxy_source.as_deref();
    if let Some(proxy) = &step.proxied_via {
        let hint = if source == Some(SOURCE_CLI) {
            "from arg --proxy".to_string()
        } else {
            format!("from env {}", source.unwrap_or(""))
        };
        return format!("Proxy: {proxy} ({hint})");
    }
    match source {
        Some(SOURCE_NO_PROXY) => "Proxy: none (bypassed by env no_proxy)".into(),
        Some(SOURCE_DISABLED) => "Proxy: disabled (from --proxy \"\")".into(),
        Some(SOURCE_NO_MATCH) => "Proxy: direct (no matching proxy scheme in env)".into(),
        _ => "Proxy: direct".into(),
    }
}

fn response_line(step: &StepMetrics, color: bool) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(status) = step.response.status {
        let style = if (200..300).contains(&status) {
            "32"
        } else if (300..400).contains(&status) {
            "33"
        } else {
            "31"
        };
        parts.push(paint(&format!("Status: {status}"), style, color));
    }
    if step.response.bytes > 0 {
        parts.push(format!("Size: {}", format_bytes_human(step.response.bytes)));
    }
    if let Some(server) = &step.response.server {
        parts.push(format!("Server: {server}"));
    }
    if let Some(location) = &step.response.location {
        parts.push(format!("→ {}", paint(location, "36", color)));
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("  {}", parts.join(" | ")))
    }
}

fn waterfall(step: &StepMetrics, color: bool) -> String {
    let phases = [
        ("DNS", step.timing.dns_ms, "36"),
        ("Connect", step.timing.connect_ms, "32"),
        ("TLS", step.timing.tls_ms, "35"),
        ("Wait", step.timing.wait_ms, "34"),
        ("Transfer", step.timing.xfer_ms, "31"),
    ];
    let mut shown: Vec<_> = phases
        .into_iter()
        .filter(|(_, duration, _)| *duration > 0.0)
        .collect();
    if shown.is_empty() {
        shown.push(phases[0]);
    }
    let total: f64 = shown.iter().map(|(_, duration, _)| *duration).sum::<f64>().max(0.001);
    let width = term_width().saturating_sub(28).clamp(10, 60);
    let mut cursor = 0usize;
    let mut out = String::new();
    for (label, duration, style) in shown {
        let mut bars = ((duration / total) * width as f64).round() as usize;
        if bars == 0 {
            bars = 1;
        }
        let offset = " ".repeat(cursor);
        let bar = "█".repeat(bars);
        let estimated = if step.timing.is_estimated && (label == "Connect" || label == "TLS") {
            " estimated"
        } else {
            ""
        };
        out.push_str(&format!(
            "  {offset}{} {label}: {duration:.1} ms{estimated}\n",
            paint(&bar, style, color)
        ));
        cursor += bars;
    }
    out.push_str(&format!("  Total: {:.1} ms\n", step.timing.total_ms));
    out
}

fn redirect_summary(steps: &[StepMetrics], color: bool) -> String {
    let mut out = panel("Redirect summary", color, "34");
    out.push_str(&format!(
        "  {:>4}  {:>6}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  URL\n",
        "Step", "Status", "DNS", "Connect", "TLS", "TTFB", "Total"
    ));
    for step in steps {
        out.push_str(&format!(
            "  {:>4}  {:>6}  {:>8.1}  {:>8.1}  {:>8.1}  {:>8.1}  {:>8.1}  {}\n",
            step.step_number,
            step.response
                .status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "-".into()),
            step.timing.dns_ms,
            step.timing.connect_ms,
            step.timing.tls_ms,
            step.timing.ttfb_ms,
            step.timing.total_ms,
            step.url
        ));
    }
    out
}

fn slo_panel(result: &SloResult, color: bool) -> String {
    let title = if result.passed() {
        paint("SLO: pass", "32", color)
    } else {
        paint("SLO: fail", "31", color)
    };
    let thresholds = result
        .thresholds_ms
        .iter()
        .map(|(key, value)| format!("{key}≤{}ms", format_threshold(*value)))
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!("{title}\nThresholds: {thresholds}\n");
    for violation in &result.violations {
        body.push_str(&format!(
            "  {}: {:.1} ms > {} ms (+{:.1} ms)\n",
            violation.key,
            violation.actual_ms,
            format_threshold(violation.threshold_ms),
            violation.delta_ms()
        ));
    }
    body
}

fn header(url: &str, color: bool) -> String {
    panel(&format!("Analyzing: {url}"), color, "34")
}

fn panel(text: &str, color: bool, style: &str) -> String {
    let text = paint(text, style, color);
    format!("\n┌ {text}\n└\n")
}

fn expiry_color(days: i64) -> &'static str {
    if days < CERT_EXPIRY_CRITICAL_DAYS {
        "31"
    } else if days < CERT_EXPIRY_WARNING_DAYS {
        "33"
    } else {
        "32"
    }
}

fn format_threshold(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value}")
    }
}

fn paint(text: &str, style: &str, color: bool) -> String {
    if color {
        format!("\u{1b}[{style}m{text}\u{1b}[0m")
    } else {
        text.to_string()
    }
}

fn term_width() -> usize {
    terminal_size::terminal_size()
        .map(|(width, _)| width.0 as usize)
        .unwrap_or(80)
}
