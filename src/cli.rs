use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{ArgGroup, Parser, ValueEnum};

use crate::analyzer::{self, determine_exit_code};
use crate::dns::Family;
use crate::exit::{self, DEFAULT_TIMEOUT_SECS};
use crate::export::{write_har, write_json, write_prometheus};
use crate::models::Method;
use crate::options::{ProxyChoice, Settings, Verify};
use crate::otlp;
use crate::proxy::{self, resolve_effective_proxy};
use crate::redact::redact_url_credentials;
use crate::render::{self, Mode, View};
use crate::slo::{self, select_step_for_evaluation};
use crate::tls;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliMethod {
    #[value(name = "GET")]
    Get,
    #[value(name = "POST")]
    Post,
    #[value(name = "PUT")]
    Put,
    #[value(name = "PATCH")]
    Patch,
    #[value(name = "DELETE")]
    Delete,
    #[value(name = "HEAD")]
    Head,
    #[value(name = "OPTIONS")]
    Options,
}

impl From<CliMethod> for Method {
    fn from(method: CliMethod) -> Self {
        match method {
            CliMethod::Get => Method::Get,
            CliMethod::Post => Method::Post,
            CliMethod::Put => Method::Put,
            CliMethod::Patch => Method::Patch,
            CliMethod::Delete => Method::Delete,
            CliMethod::Head => Method::Head,
            CliMethod::Options => Method::Options,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "net-info",
    version,
    about = "HTTP request visualizer (DNS → TCP → TLS → HTTP)",
    disable_help_subcommand = true
)]
#[command(group(ArgGroup::new("ip_family").multiple(false)))]
#[command(group(ArgGroup::new("tls_mode").multiple(false)))]
struct Cli {
    /// Target URL to analyze (must start with http:// or https://).
    url: String,

    /// HTTP method. Defaults to POST when --data is set, otherwise GET.
    #[arg(short = 'X', long = "request", visible_alias = "method", value_enum)]
    method: Option<CliMethod>,

    /// Request body. Use @filename to read from a file.
    #[arg(short = 'd', long)]
    data: Option<String>,

    /// Add a request header (repeatable). Format: Name: value.
    #[arg(short = 'H', long = "header")]
    header: Vec<String>,

    /// Follow redirects until a non-3xx response (max 10).
    #[arg(short = 'L', long = "location", visible_alias = "follow")]
    follow: bool,

    /// Abort the chain if total elapsed time exceeds SECONDS.
    #[arg(
        short = 'm',
        long = "max-time",
        visible_alias = "timeout",
        default_value_t = DEFAULT_TIMEOUT_SECS
    )]
    timeout: f64,

    /// Force HTTP/1.1.
    #[arg(long = "no-http2", visible_alias = "http1.1")]
    no_http2: bool,

    /// Exit with code 22 on HTTP 4xx/5xx after printing the report.
    #[arg(short = 'f', long = "fail")]
    fail: bool,

    /// Resolve and connect using IPv4 only.
    #[arg(short = '4', long = "ipv4", group = "ip_family")]
    ipv4: bool,

    /// Resolve and connect using IPv6 only.
    #[arg(short = '6', long = "ipv6", group = "ip_family")]
    ipv6: bool,

    /// Connect HOST:PORT to ADDR while keeping the original Host header and TLS SNI.
    #[arg(long = "resolve", value_name = "HOST:PORT:ADDR")]
    resolve: Vec<String>,

    /// Disable TLS certificate verification.
    #[arg(
        short = 'k',
        long = "insecure",
        visible_alias = "ignore-ssl",
        group = "tls_mode"
    )]
    insecure: bool,

    /// PEM CA bundle used in addition to the platform trust store.
    #[arg(long = "cacert", visible_alias = "ca-bundle", group = "tls_mode")]
    cacert: Option<PathBuf>,

    /// Proxy URL (http, https, socks5, socks5h). An empty value ignores proxy environment variables.
    #[arg(short = 'x', long = "proxy", value_name = "URL")]
    proxy: Option<String>,

    /// Print one summary line per step.
    #[arg(long)]
    compact: bool,

    /// Emit key=value metrics without the waterfall.
    #[arg(long = "metrics-only")]
    metrics_only: bool,

    /// Write the JSON report to PATH. Use - for stdout.
    #[arg(long, value_name = "PATH")]
    json: Option<String>,

    /// Write a HAR 1.2 archive to PATH. Use - for stdout.
    #[arg(long, value_name = "PATH")]
    har: Option<String>,

    /// Write Prometheus textfile metrics to PATH.
    #[arg(long, value_name = "PATH")]
    prometheus: Option<String>,

    /// Send one OTLP/HTTP JSON trace to ENDPOINT.
    #[arg(long, value_name = "ENDPOINT")]
    otlp: Option<String>,

    /// Per-phase latency budgets, for example total=500,ttfb=200.
    #[arg(long, value_name = "KEY=MS[,KEY=MS...]")]
    slo: Option<String>,

    /// Newline-delimited KEY=MS thresholds. Values from --slo win.
    #[arg(long = "slo-file", value_name = "PATH")]
    slo_file: Option<PathBuf>,
}

pub async fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let env: HashMap<String, String> = std::env::vars().collect();
    run_from(args, env).await
}

pub async fn run_from(args: Vec<String>, env: HashMap<String, String>) -> i32 {
    let mut argv = vec!["net-info".to_string()];
    argv.extend(args);
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(error) => {
            let _ = error.print();
            return if error.use_stderr() {
                exit::EXIT_USAGE
            } else {
                exit::EXIT_OK
            };
        }
    };
    match prepare(&cli, &env) {
        Ok(prepared) => execute(prepared, &env).await,
        Err(message) => {
            eprintln!("Error: {message}");
            exit::EXIT_USAGE
        }
    }
}

struct Prepared {
    cli: Cli,
    method: Method,
    body: Option<Vec<u8>>,
    headers: Vec<(String, String)>,
    settings: Settings,
    thresholds: Option<std::collections::BTreeMap<String, f64>>,
}

fn prepare(cli: &Cli, env: &HashMap<String, String>) -> Result<Prepared, String> {
    if !cli.timeout.is_finite() || cli.timeout <= 0.0 {
        return Err("Timeout must be a positive number of seconds".into());
    }
    validate_url(&cli.url)?;
    let family = if cli.ipv4 {
        Family::V4
    } else if cli.ipv6 {
        Family::V6
    } else {
        Family::Any
    };
    let resolve = parse_resolve(&cli.resolve, family)?;
    let proxy = match &cli.proxy {
        Some(value) if value.is_empty() => ProxyChoice::Disable,
        Some(value) => {
            let url = proxy::with_default_scheme(value);
            proxy::validate_proxy_url(&url)?;
            ProxyChoice::Explicit(url)
        }
        None => ProxyChoice::Environment,
    };
    let host = url::Url::parse(&cli.url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_default();
    let scheme = url::Url::parse(&cli.url)
        .map(|url| url.scheme().to_string())
        .unwrap_or_else(|_| "https".into());
    if family != Family::Any || !resolve.is_empty() {
        if let Ok(effective) = resolve_effective_proxy(&proxy, &scheme, &host, env) {
            if effective.resolves_remotely() {
                return Err(
                    "-4/-6 and --resolve cannot be used with a proxy that resolves hostnames remotely (http, https, socks5h)"
                        .into(),
                );
            }
        }
    }
    let verify = if cli.insecure {
        Verify::Insecure
    } else if let Some(path) = &cli.cacert {
        tls::ensure_crypto();
        let mut roots = rustls::RootCertStore::empty();
        tls::load_pem_certs(path, &mut roots)?;
        Verify::CustomCa(path.clone())
    } else {
        Verify::System
    };
    let (body, content_type) = match &cli.data {
        Some(data) => {
            let (bytes, content_type) = read_body(data)?;
            (Some(bytes), content_type)
        }
        None => (None, None),
    };
    let method_explicit = cli.method.is_some();
    let mut method = cli.method.map(Method::from).unwrap_or(Method::Get);
    if body.is_some() && method == Method::Get && !method_explicit {
        method = Method::Post;
    }
    if body.is_some() && matches!(method, Method::Get | Method::Head) && method_explicit {
        eprintln!(
            "Warning: {method} requests with a body are uncommon. Consider POST, PUT, or PATCH.",
            method = method.as_str()
        );
    }
    let mut headers = Vec::new();
    for raw in &cli.header {
        headers.push(parse_header(raw)?);
    }
    if let Some(content_type) = content_type {
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        {
            headers.push(("Content-Type".into(), content_type));
        }
    }
    let thresholds = slo::merge_slo(cli.slo_file.as_deref(), cli.slo.as_deref())?;
    let settings = Settings {
        follow: cli.follow,
        max_redirects: exit::MAX_REDIRECTS,
        timeout: Duration::from_secs_f64(cli.timeout),
        http2: !cli.no_http2,
        verify,
        proxy,
        family,
        resolve,
        env: env.clone(),
    };
    Ok(Prepared {
        cli: clone_cli(cli),
        method,
        body,
        headers,
        settings,
        thresholds,
    })
}

fn clone_cli(cli: &Cli) -> Cli {
    Cli {
        url: cli.url.clone(),
        method: cli.method,
        data: cli.data.clone(),
        header: cli.header.clone(),
        follow: cli.follow,
        timeout: cli.timeout,
        no_http2: cli.no_http2,
        fail: cli.fail,
        ipv4: cli.ipv4,
        ipv6: cli.ipv6,
        resolve: cli.resolve.clone(),
        insecure: cli.insecure,
        cacert: cli.cacert.clone(),
        proxy: cli.proxy.clone(),
        compact: cli.compact,
        metrics_only: cli.metrics_only,
        json: cli.json.clone(),
        har: cli.har.clone(),
        prometheus: cli.prometheus.clone(),
        otlp: cli.otlp.clone(),
        slo: cli.slo.clone(),
        slo_file: cli.slo_file.clone(),
    }
}

async fn execute(prepared: Prepared, env: &HashMap<String, String>) -> i32 {
    if prepared.cli.compact && prepared.cli.metrics_only {
        eprintln!("Warning: --compact is ignored because --metrics-only takes precedence.");
    }
    let mode = if prepared.cli.metrics_only {
        Mode::Metrics
    } else if prepared.cli.compact {
        Mode::Compact
    } else {
        Mode::Rich
    };
    let analysis = analyzer::analyze(
        &prepared.cli.url,
        prepared.method,
        prepared.body.as_deref(),
        &prepared.headers,
        &prepared.settings,
    );
    let steps = tokio::select! {
        steps = analysis => steps,
        _ = wait_for_ctrl_c() => return exit::EXIT_SIGINT,
    };
    let slo = prepared.thresholds.as_ref().and_then(|thresholds| {
        select_step_for_evaluation(&steps).and_then(|step| slo::evaluate_slo(step, thresholds).ok())
    });
    if let Some(step) = steps.iter().find(|step| step.redirect_limit_reached) {
        eprintln!(
            "Warning: {}",
            step.note.as_deref().unwrap_or("Maximum redirects followed")
        );
    }
    let rendered = render::render(
        &steps,
        &View {
            mode,
            color: colors_enabled(env, mode == Mode::Metrics),
            initial_url: redact_url_credentials(&prepared.cli.url),
            slo: slo.clone(),
        },
    );
    print!("{rendered}");
    let _ = std::io::stdout().flush();

    let mut export_failed = false;
    if let Some(path) = &prepared.cli.json {
        if let Err(err) = write_json(&steps, &redact_url_credentials(&prepared.cli.url), path, slo.as_ref())
        {
            eprintln!("Error: {err}");
            export_failed = true;
        } else if path != "-" {
            eprintln!("Exported analysis to {path}");
        }
    }
    if let Some(path) = &prepared.cli.har {
        if let Err(err) = write_har(&steps, &redact_url_credentials(&prepared.cli.url), path) {
            eprintln!("Error: {err}");
            export_failed = true;
        } else if path != "-" {
            eprintln!("Exported HAR to {path}");
        }
    }
    if let Some(path) = &prepared.cli.prometheus {
        if let Err(err) = write_prometheus(&steps, path) {
            eprintln!("Error: {err}");
            export_failed = true;
        } else {
            eprintln!("Exported Prometheus metrics to {path}");
        }
    }
    if let Some(endpoint) = &prepared.cli.otlp {
        if let Err(err) = otlp::export(endpoint, &steps, prepared.settings.timeout).await {
            eprintln!("Error: {err}");
            export_failed = true;
        } else {
            eprintln!("Exported OTLP trace to {endpoint}");
        }
    }
    determine_exit_code(
        &steps,
        slo.as_ref().is_some_and(|result| !result.passed()),
        prepared.cli.fail,
        export_failed,
    )
}

async fn wait_for_ctrl_c() {
    let _ = tokio::signal::ctrl_c().await;
}

fn colors_enabled(env: &HashMap<String, String>, metrics: bool) -> bool {
    if metrics {
        return false;
    }
    let dumb = env.get("TERM").map(String::as_str) == Some("dumb");
    if env.contains_key("FORCE_COLOR") {
        return true;
    }
    if dumb || env.contains_key("NO_COLOR") {
        return false;
    }
    std::io::stdout().is_terminal()
}

fn validate_url(url: &str) -> Result<(), String> {
    if url.chars().any(char::is_whitespace) {
        return Err("Invalid URL: whitespace is not allowed".into());
    }
    let parsed = url::Url::parse(url).map_err(|err| format!("Invalid URL: {err}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!("Invalid URL: unsupported scheme '{}'", parsed.scheme()));
    }
    if parsed.host_str().is_none() {
        return Err("Invalid URL: missing host".into());
    }
    if parsed.port() == Some(0) {
        return Err("Invalid URL: port must be between 1 and 65535".into());
    }
    Ok(())
}

fn parse_resolve(
    values: &[String],
    family: Family,
) -> Result<HashMap<(String, u16), IpAddr>, String> {
    let mut entries = HashMap::new();
    for value in values {
        let Some((host, remainder)) = value.split_once(':') else {
            return Err(format!("Invalid --resolve value '{value}'; expected HOST:PORT:ADDR"));
        };
        let Some((port_text, address)) = remainder.split_once(':') else {
            return Err(format!("Invalid --resolve value '{value}'; expected HOST:PORT:ADDR"));
        };
        if host.is_empty()
            || port_text.is_empty()
            || address.is_empty()
            || host != host.trim()
            || port_text != port_text.trim()
            || address != address.trim()
        {
            return Err(format!("Invalid --resolve value '{value}'; expected HOST:PORT:ADDR"));
        }
        let port: u16 = port_text.parse().map_err(|_| {
            format!("Invalid --resolve port '{port_text}'; expected 1-65535")
        })?;
        if port == 0 {
            return Err(format!("Invalid --resolve port '{port_text}'; expected 1-65535"));
        }
        let address = address
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(address);
        let ip: IpAddr = address.parse().map_err(|_| {
            format!("Invalid --resolve address '{address}'; expected an IPv4 or IPv6 address")
        })?;
        if (family == Family::V4 && ip.is_ipv6()) || (family == Family::V6 && ip.is_ipv4()) {
            let expected = if family == Family::V4 { "ipv4" } else { "ipv6" };
            return Err(format!(
                "--resolve address '{address}' does not match --{expected}"
            ));
        }
        let key = (host.to_ascii_lowercase(), port);
        if entries.contains_key(&key) {
            return Err(format!("Duplicate --resolve entry for {host}:{port}"));
        }
        entries.insert(key, ip);
    }
    Ok(entries)
}

fn parse_header(raw: &str) -> Result<(String, String), String> {
    let Some((name, value)) = raw.split_once(':') else {
        return Err(format!("Invalid header '{raw}'; expected Name: value"));
    };
    let name = name.trim();
    let value = value.trim();
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'))
    {
        return Err(format!("Invalid header name '{name}'"));
    }
    if value.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
        return Err("Header values cannot contain CR or LF".into());
    }
    Ok((name.to_string(), value.to_string()))
}

fn read_body(data: &str) -> Result<(Vec<u8>, Option<String>), String> {
    if let Some(path) = data.strip_prefix('@') {
        if path.is_empty() {
            return Err("Error reading data: missing filename after @".into());
        }
        let bytes = std::fs::read(path).map_err(|err| format!("Error reading data: {err}"))?;
        let content_type = match std::path::Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
        {
            Some("json") => Some("application/json".into()),
            Some("xml") => Some("application/xml".into()),
            Some("txt") | Some("text") => Some("text/plain".into()),
            _ => None,
        };
        return Ok((bytes, content_type));
    }
    let bytes = data.as_bytes().to_vec();
    let content_type = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .map(|_| "application/json".to_string());
    Ok((bytes, content_type))
}
