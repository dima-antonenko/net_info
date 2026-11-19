use std::collections::BTreeMap;
use std::path::Path;

use crate::models::StepMetrics;

pub const SLO_KEYS: &[&str] = &["connect", "dns", "tls", "total", "ttfb", "wait", "xfer"];

#[derive(Debug, Clone, PartialEq)]
pub struct SloViolation {
    pub key: String,
    pub threshold_ms: f64,
    pub actual_ms: f64,
}

impl SloViolation {
    pub fn delta_ms(&self) -> f64 {
        self.actual_ms - self.threshold_ms
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SloResult {
    pub thresholds_ms: BTreeMap<String, f64>,
    pub violations: Vec<SloViolation>,
}

impl SloResult {
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "pass": self.passed(),
            "thresholds_ms": self.thresholds_ms,
            "violations": self.violations.iter().map(|violation| {
                serde_json::json!({
                    "key": violation.key,
                    "threshold_ms": violation.threshold_ms,
                    "actual_ms": violation.actual_ms,
                    "delta_ms": violation.delta_ms(),
                })
            }).collect::<Vec<_>>(),
        })
    }
}

pub fn parse_slo_spec(raw: &str) -> Result<BTreeMap<String, f64>, String> {
    let mut thresholds = BTreeMap::new();
    if raw.trim().is_empty() {
        return Err("SLO specification is empty".into());
    }
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err("SLO specification contains an empty entry".into());
        }
        let Some((key_raw, value_raw)) = part.split_once('=') else {
            return Err(format!(
                "Invalid SLO entry '{part}': expected KEY=MS"
            ));
        };
        let key = key_raw.trim().to_ascii_lowercase();
        if !SLO_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "Unknown SLO key '{key}'. Valid keys: {}.",
                SLO_KEYS.join(", ")
            ));
        }
        if thresholds.contains_key(&key) {
            return Err(format!("Duplicate SLO key '{key}'"));
        }
        let value: f64 = value_raw.trim().parse().map_err(|_| {
            format!("Invalid SLO value for '{key}': '{}' must be a positive finite number of milliseconds.", value_raw.trim())
        })?;
        if !value.is_finite() || value <= 0.0 {
            return Err(format!(
                "Invalid SLO value for '{key}': '{}' must be a positive finite number of milliseconds.",
                value_raw.trim()
            ));
        }
        thresholds.insert(key, value);
    }
    Ok(thresholds)
}

pub fn parse_slo_file(path: &Path) -> Result<BTreeMap<String, f64>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("Failed to read SLO file '{}': {err}", path.display()))?;
    let raw = raw.trim_start_matches('\u{feff}');
    let specification = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join(",");
    parse_slo_spec(&specification)
        .map_err(|err| format!("Invalid SLO file '{}': {err}", path.display()))
}

pub fn merge_slo(
    file: Option<&Path>,
    cli: Option<&str>,
) -> Result<Option<BTreeMap<String, f64>>, String> {
    let mut thresholds = match file {
        Some(path) => parse_slo_file(path)?,
        None => BTreeMap::new(),
    };
    if let Some(spec) = cli {
        for (key, value) in parse_slo_spec(spec)? {
            thresholds.insert(key, value);
        }
    }
    if thresholds.is_empty() {
        Ok(None)
    } else {
        Ok(Some(thresholds))
    }
}

pub fn evaluate_slo(
    step: &StepMetrics,
    thresholds: &BTreeMap<String, f64>,
) -> Result<SloResult, String> {
    for key in thresholds.keys() {
        if step.timing.phase(key).is_none() {
            return Err(format!(
                "Unknown SLO key '{key}'. Valid keys: {}.",
                SLO_KEYS.join(", ")
            ));
        }
    }
    let violations = thresholds
        .iter()
        .filter_map(|(key, threshold)| {
            let actual = step.timing.phase(key)?;
            (actual > *threshold).then(|| SloViolation {
                key: key.clone(),
                threshold_ms: *threshold,
                actual_ms: actual,
            })
        })
        .collect();
    Ok(SloResult {
        thresholds_ms: thresholds.clone(),
        violations,
    })
}

pub fn select_step_for_evaluation(steps: &[StepMetrics]) -> Option<&StepMetrics> {
    steps.iter().rev().find(|step| !step.has_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::TimingMetrics;

    #[test]
    fn parses_and_rejects_bad_specs() {
        let parsed = parse_slo_spec("Total=500,ttfb=200").unwrap();
        assert_eq!(parsed["total"], 500.0);
        assert!(parse_slo_spec("nope=1").is_err());
        assert!(parse_slo_spec("dns=0").is_err());
        assert!(parse_slo_spec("dns=1,dns=2").is_err());
    }

    #[test]
    fn evaluates_the_final_successful_step() {
        let mut slow = StepMetrics {
            url: "https://example.com".into(),
            step_number: 1,
            timing: TimingMetrics {
                total_ms: 800.0,
                ttfb_ms: 100.0,
                ..TimingMetrics::default()
            },
            ..empty_step()
        };
        slow.timing.finalize(true);
        let thresholds = parse_slo_spec("total=500,ttfb=200").unwrap();
        let result = evaluate_slo(&slow, &thresholds).unwrap();
        assert!(!result.passed());
        assert_eq!(result.violations[0].key, "total");
    }

    fn empty_step() -> StepMetrics {
        StepMetrics {
            url: String::new(),
            step_number: 1,
            timing: TimingMetrics::default(),
            network: Default::default(),
            response: Default::default(),
            error: None,
            error_kind: None,
            note: None,
            proxied_via: None,
            request_method: None,
            request_headers: Vec::new(),
            request_body_bytes: 0,
            redirect_limit_reached: false,
        }
    }
}
