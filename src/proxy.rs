use std::collections::HashMap;

use url::Url;

use crate::options::ProxyChoice;
use crate::redact::redact_url_credentials;

pub const SOURCE_CLI: &str = "--proxy";
pub const SOURCE_NO_PROXY: &str = "NO_PROXY";
pub const SOURCE_DISABLED: &str = "noproxy";
pub const SOURCE_NO_MATCH: &str = "no_proxy_env";

const PROXY_SCHEMES: &[&str] = &["http", "https", "socks5", "socks5h"];
const REMOTE_DNS: &[&str] = &["http", "https", "socks5h"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveProxy {
    pub url: Option<String>,
    pub source: Option<String>,
}

impl EffectiveProxy {
    pub fn resolves_remotely(&self) -> bool {
        self.url
            .as_deref()
            .and_then(|url| url.split("://").next())
            .is_some_and(|scheme| REMOTE_DNS.contains(&scheme.to_ascii_lowercase().as_str()))
    }
}

pub fn with_default_scheme(value: &str) -> String {
    if value.contains("://") {
        value.to_string()
    } else {
        format!("http://{value}")
    }
}

pub fn proxy_url_problem(proxy_url: &str) -> Option<String> {
    let parsed = Url::parse(proxy_url).ok()?;
    if !PROXY_SCHEMES.contains(&parsed.scheme()) {
        return Some(format!(
            "unsupported scheme '{}'; expected one of {}",
            parsed.scheme(),
            PROXY_SCHEMES.join(", ")
        ));
    }
    if parsed.host_str().is_none() {
        return Some("missing host".into());
    }
    if let Some(port) = parsed.port() {
        if port == 0 {
            return Some("port 0 out of range 1-65535".into());
        }
    }
    None
}

pub fn validate_proxy_url(proxy_url: &str) -> Result<(), String> {
    if Url::parse(proxy_url).is_err() {
        return Err("malformed URL".into());
    }
    if let Some(problem) = proxy_url_problem(proxy_url) {
        return Err(problem);
    }
    Ok(())
}

pub fn host_matches_no_proxy(host: &str, no_proxy: &str) -> bool {
    if no_proxy.is_empty() {
        return false;
    }
    let host = host.to_ascii_lowercase();
    no_proxy
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .any(|pattern| {
            let pattern = pattern.to_ascii_lowercase();
            pattern == "*"
                || pattern == host
                || (pattern.starts_with('.') && host.ends_with(&pattern))
                || host.ends_with(&format!(".{pattern}"))
        })
}

fn env_value<'a>(env: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    env.get(key).map(String::as_str).filter(|value| !value.is_empty())
}

fn env_defined(env: &HashMap<String, String>, key: &str) -> bool {
    env.contains_key(key)
}

pub fn resolve_effective_proxy(
    choice: &ProxyChoice,
    scheme: &str,
    host: &str,
    env: &HashMap<String, String>,
) -> Result<EffectiveProxy, String> {
    match choice {
        ProxyChoice::Disable => {
            return Ok(EffectiveProxy {
                url: None,
                source: Some(SOURCE_DISABLED.into()),
            });
        }
        ProxyChoice::Explicit(value) => {
            let url = with_default_scheme(value);
            validate_proxy_url(&url)?;
            return Ok(EffectiveProxy {
                url: Some(url),
                source: Some(SOURCE_CLI.into()),
            });
        }
        ProxyChoice::Environment => {}
    }

    let no_proxy = if env_defined(env, "no_proxy") {
        env.get("no_proxy").cloned().unwrap_or_default()
    } else {
        env.get("NO_PROXY").cloned().unwrap_or_default()
    };
    if host_matches_no_proxy(host, &no_proxy) {
        return Ok(EffectiveProxy {
            url: None,
            source: Some(SOURCE_NO_PROXY.into()),
        });
    }

    let scheme_lower = scheme.to_ascii_lowercase();
    let scheme_upper = scheme.to_ascii_uppercase();
    for name in [
        format!("{scheme_lower}_proxy"),
        format!("{scheme_upper}_PROXY"),
        "all_proxy".into(),
        "ALL_PROXY".into(),
    ] {
        if let Some(value) = env_value(env, &name) {
            let url = with_default_scheme(value);
            if let Err(problem) = validate_proxy_url(&url) {
                return Err(format!(
                    "Invalid proxy URL in {name}: {} ({problem})",
                    redact_url_credentials(&url)
                ));
            }
            return Ok(EffectiveProxy {
                url: Some(url),
                source: Some(name),
            });
        }
    }

    let any = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]
        .into_iter()
        .any(|name| env_value(env, name).is_some());
    if any {
        return Ok(EffectiveProxy {
            url: None,
            source: Some(SOURCE_NO_MATCH.into()),
        });
    }
    Ok(EffectiveProxy {
        url: None,
        source: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_proxy_matches_suffix_and_wildcard() {
        assert!(host_matches_no_proxy("api.example.com", "example.com"));
        assert!(host_matches_no_proxy("api.example.com", ".example.com"));
        assert!(host_matches_no_proxy("localhost", "*"));
        assert!(!host_matches_no_proxy("example.org", "example.com"));
    }

    #[test]
    fn explicit_proxy_beats_environment() {
        let mut env = HashMap::new();
        env.insert("https_proxy".into(), "http://env:3128".into());
        let effective = resolve_effective_proxy(
            &ProxyChoice::Explicit("socks5://proxy:1080".into()),
            "https",
            "example.com",
            &env,
        )
        .unwrap();
        assert_eq!(effective.url.as_deref(), Some("socks5://proxy:1080"));
        assert!(!effective.resolves_remotely());
    }

    #[test]
    fn lowercase_scheme_proxy_is_preferred() {
        let mut env = HashMap::new();
        env.insert("https_proxy".into(), "http://lower:1".into());
        env.insert("HTTPS_PROXY".into(), "http://upper:1".into());
        let effective = resolve_effective_proxy(
            &ProxyChoice::Environment,
            "https",
            "example.com",
            &env,
        )
        .unwrap();
        assert_eq!(effective.url.as_deref(), Some("http://lower:1"));
        assert!(effective.resolves_remotely());
    }
}
