use std::time::Instant;

use url::Url;

use crate::client::{self, RequestError};
use crate::models::{Method, ResponseInfo, StepMetrics, TimingMetrics};
use crate::options::Settings;
use crate::redact::{redact_url_credentials, sanitize_headers};

const ORIGIN_BOUND: &[&str] = &["authorization", "cookie", "host", "proxy-authorization"];
const BODY_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "content-encoding",
    "transfer-encoding",
];

pub async fn analyze(
    url: &str,
    method: Method,
    body: Option<&[u8]>,
    headers: &[(String, String)],
    settings: &Settings,
) -> Vec<StepMetrics> {
    let mut steps = Vec::new();
    let mut current = match Url::parse(url) {
        Ok(url) => url,
        Err(err) => {
            steps.push(failed_step(
                redact_url_credentials(url),
                1,
                method,
                headers,
                body.map(|bytes| bytes.len() as u64).unwrap_or(0),
                format!("Invalid URL: {err}"),
                "network",
            ));
            return steps;
        }
    };
    let mut method = method;
    let mut body = body.map(|bytes| bytes.to_vec());
    let mut headers = headers.to_vec();
    let deadline = Instant::now() + settings.timeout;
    let mut redirects = 0usize;

    loop {
        let step_number = steps.len() + 1;
        let mut step = request_step(
            &current,
            step_number,
            method,
            body.as_deref(),
            &headers,
            deadline,
            settings,
        )
        .await;
        let location = step.response.location.clone();
        if let Some(value) = &mut step.response.location {
            *value = redact_url_credentials(value);
        }
        let redirecting = settings.follow && step.error.is_none() && is_redirect(step.response.status, location.as_deref());
        steps.push(step);
        if !redirecting {
            break;
        }
        let Some(location) = location else {
            break;
        };
        if redirects == settings.max_redirects {
            let step = steps.last_mut().expect("step was just pushed");
            step.note = Some(format!(
                "Maximum redirects followed ({})",
                settings.max_redirects
            ));
            step.redirect_limit_reached = true;
            break;
        }
        let next_method = redirect_method(steps.last().and_then(|step| step.response.status).unwrap_or(0), method);
        let next_url = match current.join(&location) {
            Ok(url) => url,
            Err(err) => {
                steps.push(failed_step(
                    redact_url_credentials(&location),
                    step_number + 1,
                    next_method,
                    &[],
                    0,
                    format!("Invalid redirect target: {err}"),
                    "network",
                ));
                break;
            }
        };
        if !matches!(next_url.scheme(), "http" | "https") || next_url.host_str().is_none() {
            steps.push(failed_step(
                redact_url_credentials(next_url.as_str()),
                step_number + 1,
                next_method,
                &[],
                0,
                format!(
                    "Invalid redirect target: {}",
                    if next_url.host_str().is_none() {
                        "missing host".to_string()
                    } else {
                        format!("unsupported scheme '{}'", next_url.scheme())
                    }
                ),
                "network",
            ));
            break;
        }
        let keep_credentials = same_origin_or_https_upgrade(&current, &next_url);
        let keep_body = next_method == method;
        headers = filter_redirect_headers(&headers, keep_credentials, keep_body);
        if !keep_body {
            body = None;
        }
        method = next_method;
        current = next_url;
        redirects += 1;
    }
    steps
}

fn is_redirect(status: Option<u16>, location: Option<&str>) -> bool {
    matches!(status, Some(code) if (300..400).contains(&code)) && location.is_some()
}

pub fn redirect_method(status: u16, method: Method) -> Method {
    if status == 303 && method != Method::Head {
        Method::Get
    } else if (status == 301 || status == 302) && method == Method::Post {
        Method::Get
    } else {
        method
    }
}

pub fn filter_redirect_headers(
    headers: &[(String, String)],
    keep_credentials: bool,
    keep_body_headers: bool,
) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            (keep_credentials || !ORIGIN_BOUND.contains(&lower.as_str()))
                && (keep_body_headers || !BODY_HEADERS.contains(&lower.as_str()))
        })
        .cloned()
        .collect()
}

fn same_origin_or_https_upgrade(current: &Url, next: &Url) -> bool {
    origin(current) == origin(next)
        || (origin(current) == ("http", host_of(next), 80) && origin(next) == ("https", host_of(current), 443)
            && host_of(current) == host_of(next))
}

fn origin(url: &Url) -> (&str, String, u16) {
    let port = url.port_or_known_default().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    (url.scheme(), host_of(url), port)
}

fn host_of(url: &Url) -> String {
    url.host_str().unwrap_or("").to_ascii_lowercase()
}

async fn request_step(
    url: &Url,
    step_number: usize,
    method: Method,
    body: Option<&[u8]>,
    headers: &[(String, String)],
    deadline: Instant,
    settings: &Settings,
) -> StepMetrics {
    let mut step = StepMetrics {
        url: redact_url_credentials(url.as_str()),
        step_number,
        timing: TimingMetrics::default(),
        network: Default::default(),
        response: ResponseInfo::default(),
        error: None,
        error_kind: None,
        note: None,
        proxied_via: None,
        request_method: Some(method.as_str().into()),
        request_headers: sanitize_headers(headers),
        request_body_bytes: body.map(|bytes| bytes.len() as u64).unwrap_or(0),
        redirect_limit_reached: false,
    };
    if Instant::now() >= deadline {
        step.error = Some("Request timeout exhausted".into());
        step.error_kind = Some("network".into());
        step.note = Some(format!("Step {step_number}: Request failed"));
        return step;
    }
    match client::perform(url, method, body, headers, deadline, settings).await {
        Ok(outcome) => {
            step.timing = outcome.timing;
            step.network = outcome.network;
            step.response = outcome.response;
            step.proxied_via = step.network.proxy_url.clone();
        }
        Err(error) => apply_error(&mut step, error, step_number),
    }
    step
}

fn apply_error(step: &mut StepMetrics, error: RequestError, step_number: usize) {
    step.error = Some(error.message);
    step.error_kind = Some(error.kind.into());
    step.timing = error.timing;
    step.network = error.network;
    if let Some(response) = error.response {
        step.response = response;
    }
    step.proxied_via = step.network.proxy_url.clone();
    step.note = Some(format!("Step {step_number}: Request failed"));
}

fn failed_step(
    url: String,
    step_number: usize,
    method: Method,
    headers: &[(String, String)],
    body_bytes: u64,
    message: String,
    kind: &str,
) -> StepMetrics {
    StepMetrics {
        url,
        step_number,
        timing: TimingMetrics::default(),
        network: Default::default(),
        response: ResponseInfo::default(),
        error: Some(message),
        error_kind: Some(kind.into()),
        note: Some(format!("Step {step_number}: Request failed")),
        proxied_via: None,
        request_method: Some(method.as_str().into()),
        request_headers: sanitize_headers(headers),
        request_body_bytes: body_bytes,
        redirect_limit_reached: false,
    }
}

pub fn determine_exit_code(
    steps: &[StepMetrics],
    slo_failed: bool,
    fail_on_http: bool,
    export_failed: bool,
) -> i32 {
    if steps.is_empty() || steps.iter().any(|step| step.error_kind.as_deref() == Some("internal")) {
        return crate::exit::EXIT_SOFTWARE;
    }
    if steps.iter().any(|step| step.redirect_limit_reached) {
        return crate::exit::EXIT_REDIRECTS;
    }
    if steps.iter().any(|step| step.has_error()) {
        return crate::exit::EXIT_TEMPFAIL;
    }
    if export_failed {
        return crate::exit::EXIT_CANTCREAT;
    }
    if fail_on_http
        && steps
            .iter()
            .any(|step| step.response.status.is_some_and(|status| status >= 400))
    {
        return crate::exit::EXIT_HTTP;
    }
    if slo_failed {
        return crate::exit::EXIT_SLO;
    }
    crate::exit::EXIT_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_becomes_get_on_301_and_drops_body_headers() {
        assert_eq!(redirect_method(301, Method::Post), Method::Get);
        assert_eq!(redirect_method(303, Method::Head), Method::Head);
        assert_eq!(redirect_method(307, Method::Post), Method::Post);
        let headers = filter_redirect_headers(
            &[
                ("Authorization".into(), "secret".into()),
                ("Content-Type".into(), "application/json".into()),
                ("Accept".into(), "application/json".into()),
            ],
            false,
            false,
        );
        assert_eq!(headers, vec![("Accept".into(), "application/json".into())]);
    }

    #[test]
    fn exit_precedence() {
        let mut step = failed_step("http://x".into(), 1, Method::Get, &[], 0, "boom".into(), "network");
        assert_eq!(determine_exit_code(&[step.clone()], true, true, true), crate::exit::EXIT_TEMPFAIL);
        step.error = None;
        step.error_kind = None;
        step.redirect_limit_reached = true;
        assert_eq!(determine_exit_code(&[step.clone()], false, false, false), crate::exit::EXIT_REDIRECTS);
        step.redirect_limit_reached = false;
        step.response.status = Some(500);
        assert_eq!(determine_exit_code(&[step.clone()], true, true, true), crate::exit::EXIT_CANTCREAT);
        assert_eq!(determine_exit_code(&[step.clone()], true, true, false), crate::exit::EXIT_HTTP);
        step.response.status = Some(200);
        assert_eq!(determine_exit_code(&[step], true, true, false), crate::exit::EXIT_SLO);
    }
}
