const MASK: &str = "****";
const SENSITIVE: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "api-key",
    "x-api-key",
];
const URL_HEADERS: &[&str] = &["location", "content-location"];

pub fn mask_sensitive_value(value: &str) -> String {
    const SHOW: usize = 4;
    if value.chars().count() <= SHOW * 2 {
        return MASK.to_string();
    }
    let prefix: String = value.chars().take(SHOW).collect();
    let suffix: String = value
        .chars()
        .rev()
        .take(SHOW)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{prefix}{MASK}{suffix}")
}

pub fn redact_url_credentials(url: &str) -> String {
    // Scheme-less values such as `user:secret@proxy:3128` are masked too.
    let (prefix, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), url),
    };
    let Some(at) = rest.find('@') else {
        return url.to_string();
    };
    let userinfo = &rest[..at];
    let hostport = &rest[at + 1..];
    if userinfo.is_empty() {
        return url.to_string();
    }
    let masked = if let Some((user, _)) = userinfo.split_once(':') {
        format!("{user}:{MASK}")
    } else {
        MASK.to_string()
    };
    format!("{prefix}{masked}@{hostport}")
}

pub fn sanitize_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let lower = name.to_ascii_lowercase();
            let value = if SENSITIVE.contains(&lower.as_str()) {
                mask_sensitive_value(value)
            } else if URL_HEADERS.contains(&lower.as_str()) {
                redact_url_credentials(value)
            } else {
                value.clone()
            };
            (name.clone(), value)
        })
        .collect()
}

pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(value) = u8::from_str_radix(
                std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or(""),
                16,
            ) {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn format_metric_value(value: &str) -> String {
    const SAFE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.~,-*:+/@[]";
    if value.chars().all(|ch| SAFE.contains(ch)) {
        return value.to_string();
    }
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        if SAFE.as_bytes().contains(byte) {
            encoded.push(*byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

pub fn format_bytes_human(num_bytes: u64) -> String {
    let kib = num_bytes as f64 / 1024.0;
    if kib < 1.0 {
        format!("{num_bytes} B")
    } else if kib < 1024.0 {
        format!("{kib:.1} KB")
    } else {
        format!("{:.1} MB", kib / 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_long_secrets_and_short_ones() {
        assert_eq!(mask_sensitive_value("Bearer token123456"), "Bear****3456");
        assert_eq!(mask_sensitive_value("short"), "****");
    }

    #[test]
    fn redacts_userinfo() {
        assert_eq!(
            redact_url_credentials("http://user:secret@proxy:3128"),
            "http://user:****@proxy:3128"
        );
        assert_eq!(
            redact_url_credentials("socks5h://token@gateway:1080"),
            "socks5h://****@gateway:1080"
        );
        assert_eq!(
            redact_url_credentials("http://proxy:3128"),
            "http://proxy:3128"
        );
    }

    #[test]
    fn sanitizes_authorization_and_location() {
        let headers = sanitize_headers(&[
            ("Authorization".into(), "Bearer secret".into()),
            (
                "Location".into(),
                "https://user:secret@example.com/".into(),
            ),
        ]);
        assert_eq!(headers[0].1, "Bear****cret");
        assert_eq!(headers[1].1, "https://user:****@example.com/");
    }
}
