use std::collections::{BTreeMap, HashMap, HashSet};

use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::Sha256;

use crate::model::{
    Action, Coverage, CoverageStatus, Decision, Envelope, Finding, InternalFinding, Location, Mode,
    Policy, Rule, RulePack, Versions,
};
use crate::validators;

type HmacSha256 = Hmac<Sha256>;

pub fn validate_rule_packs(packs: &[RulePack]) -> Result<(), String> {
    let mut ids = HashSet::new();
    for pack in packs {
        if pack.manifest.api_version != 1 {
            return Err(format!(
                "rule pack {} uses unsupported apiVersion {}",
                pack.manifest.id, pack.manifest.api_version
            ));
        }
        if pack.manifest.id.trim().is_empty() || pack.manifest.version.trim().is_empty() {
            return Err("rule pack manifest id and version are required".to_owned());
        }
        let engine_version = semver::Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(|error| format!("invalid engine version: {error}"))?;
        let minimum =
            semver::Version::parse(&pack.manifest.min_engine_version).map_err(|error| {
                format!(
                    "rule pack {} has invalid minEngineVersion: {error}",
                    pack.manifest.id
                )
            })?;
        if minimum > engine_version {
            return Err(format!(
                "rule pack {} requires engine {}, current engine is {}",
                pack.manifest.id, minimum, engine_version
            ));
        }
        for rule in &pack.rules {
            if !ids.insert(rule.id.clone()) {
                return Err(format!("duplicate rule id: {}", rule.id));
            }
            if rule.kind != "text" && rule.kind != "path" {
                return Err(format!(
                    "rule {} has unsupported kind {}",
                    rule.id, rule.kind
                ));
            }
            Regex::new(&rule.pattern)
                .map_err(|error| format!("rule {} has invalid regex: {error}", rule.id))?;
            if rule.explanation.trim().is_empty() || rule.remediation.trim().is_empty() {
                return Err(format!(
                    "rule {} needs explanation and remediation",
                    rule.id
                ));
            }
            if let Some(validator) = &rule.validator
                && ![
                    "none",
                    "luhn",
                    "iban",
                    "ipv4",
                    "vn_cccd",
                    "vn_tax_id",
                    "entropy",
                ]
                .contains(&validator.as_str())
            {
                return Err(format!(
                    "rule {} has unknown validator {validator}",
                    rule.id
                ));
            }
        }
    }
    Ok(())
}

pub fn scan_envelope(
    envelope: &Envelope,
    policy: &Policy,
    packs: &[RulePack],
    hmac_key: &[u8],
) -> Result<Decision, String> {
    validate_rule_packs(packs)?;
    validate_envelope(envelope)?;
    if hmac_key.len() < 16 {
        return Err("HMAC key must be at least 16 bytes".to_owned());
    }

    let mut internal = Vec::new();
    for pack in packs {
        for rule in &pack.rules {
            if rule.kind == "path" {
                scan_path_rule(envelope, rule, hmac_key, &mut internal)?;
            } else {
                for segment in &envelope.segments {
                    scan_text_rule(
                        segment.id.as_str(),
                        segment.text.as_str(),
                        rule,
                        hmac_key,
                        &mut internal,
                    )?;
                }
            }
        }
    }

    internal.sort_by(|left, right| {
        left.public
            .location
            .segment_id
            .cmp(&right.public.location.segment_id)
            .then(left.public.location.start.cmp(&right.public.location.start))
            .then(right.public.severity.cmp(&left.public.severity))
            .then(right.public.confidence.cmp(&left.public.confidence))
    });
    internal.dedup_by(|left, right| {
        left.public.rule_id == right.public.rule_id
            && left.public.location.segment_id == right.public.location.segment_id
            && left.public.location.start == right.public.location.start
            && left.public.location.end == right.public.location.end
    });

    internal.retain(|finding| !is_suppressed(finding, envelope, policy));

    let mut action = internal
        .iter()
        .map(|finding| {
            policy
                .actions
                .get(&finding.public.category)
                .copied()
                .unwrap_or(finding.action)
        })
        .max_by_key(|candidate| candidate.rank())
        .unwrap_or(Action::Allow);

    if policy.mode == Mode::Audit && !internal.is_empty() {
        action = Action::Warn;
    } else if policy.mode == Mode::Enforce && action == Action::Ask {
        action = Action::Block;
    }

    let should_redact = policy.mode != Mode::Audit && (policy.redact || action == Action::Redact);
    let transformed = should_redact.then(|| transform(envelope, &internal));
    let findings = internal.into_iter().map(|finding| finding.public).collect();

    let rule_packs = packs
        .iter()
        .map(|pack| (pack.manifest.id.clone(), pack.manifest.version.clone()))
        .collect::<BTreeMap<_, _>>();

    Ok(Decision {
        action,
        findings,
        transformed,
        coverage: Coverage {
            status: CoverageStatus::Complete,
            degraded_detectors: Vec::new(),
        },
        versions: Versions {
            engine: env!("CARGO_PKG_VERSION").to_owned(),
            policy: policy.version.to_string(),
            rule_packs,
        },
    })
}

fn validate_envelope(envelope: &Envelope) -> Result<(), String> {
    if ![
        "to_model",
        "from_model",
        "tool_call",
        "tool_result",
        "memory_write",
    ]
    .contains(&envelope.direction.as_str())
    {
        return Err(format!(
            "unsupported envelope direction: {}",
            envelope.direction
        ));
    }
    if !["trusted", "untrusted", "unknown"].contains(&envelope.source.trust.as_str()) {
        return Err(format!(
            "unsupported source trust value: {}",
            envelope.source.trust
        ));
    }
    if envelope.media_type.trim().is_empty() {
        return Err("envelope mediaType is required".to_owned());
    }
    if envelope.segments.is_empty() {
        return Err("envelope must contain at least one segment".to_owned());
    }
    let mut ids = HashSet::new();
    for segment in &envelope.segments {
        if segment.id.trim().is_empty() {
            return Err("segment id must not be empty".to_owned());
        }
        if !ids.insert(segment.id.as_str()) {
            return Err(format!("duplicate segment id: {}", segment.id));
        }
    }
    Ok(())
}

fn scan_path_rule(
    envelope: &Envelope,
    rule: &Rule,
    hmac_key: &[u8],
    findings: &mut Vec<InternalFinding>,
) -> Result<(), String> {
    let Some(path) = envelope.source.name.as_deref() else {
        return Ok(());
    };
    let regex = Regex::new(&rule.pattern).map_err(|error| error.to_string())?;
    if regex.is_match(path) {
        let fingerprint = fingerprint(hmac_key, path.as_bytes())?;
        findings.push(InternalFinding {
            public: Finding {
                rule_id: rule.id.clone(),
                category: rule.category.clone(),
                severity: rule.severity,
                confidence: rule.confidence,
                location: Location {
                    segment_id: envelope
                        .segments
                        .first()
                        .map_or_else(|| "source".to_owned(), |segment| segment.id.clone()),
                    start: 0,
                    end: 0,
                },
                masked_preview: "[SENSITIVE PATH]".to_owned(),
                fingerprint,
                explanation: rule.explanation.clone(),
                remediation: rule.remediation.clone(),
            },
            action: rule.action,
        });
    }
    Ok(())
}

fn scan_text_rule(
    segment_id: &str,
    text: &str,
    rule: &Rule,
    hmac_key: &[u8],
    findings: &mut Vec<InternalFinding>,
) -> Result<(), String> {
    let regex = Regex::new(&rule.pattern).map_err(|error| error.to_string())?;
    scan_view(
        segment_id, text, text, None, rule, &regex, hmac_key, findings,
    )?;

    if contains_zero_width(text) {
        let (canonical, byte_map) = remove_zero_width(text);
        scan_view(
            segment_id,
            text,
            &canonical,
            Some(&byte_map),
            rule,
            &regex,
            hmac_key,
            findings,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn scan_view(
    segment_id: &str,
    original: &str,
    view: &str,
    byte_map: Option<&[usize]>,
    rule: &Rule,
    regex: &Regex,
    hmac_key: &[u8],
    findings: &mut Vec<InternalFinding>,
) -> Result<(), String> {
    for matched in regex.find_iter(view) {
        let (start, end) = if let Some(map) = byte_map {
            let start = map.get(matched.start()).copied().unwrap_or(original.len());
            let end = map.get(matched.end()).copied().unwrap_or(original.len());
            (start, end)
        } else {
            (matched.start(), matched.end())
        };
        if start >= end || !original.is_char_boundary(start) || !original.is_char_boundary(end) {
            continue;
        }
        let raw = &original[start..end];
        let context = context_window(original, start, end).to_lowercase();
        let has_context = rule
            .context
            .iter()
            .any(|word| context.contains(&word.to_lowercase()));
        let has_negative_context = rule
            .negative_context
            .iter()
            .any(|word| context.contains(&word.to_lowercase()));
        if (rule.requires_context && !has_context) || has_negative_context {
            continue;
        }
        if !validators::validate(rule.validator.as_deref(), raw, rule.min_entropy) {
            continue;
        }

        findings.push(InternalFinding {
            public: Finding {
                rule_id: rule.id.clone(),
                category: rule.category.clone(),
                severity: rule.severity,
                confidence: rule.confidence,
                location: Location {
                    segment_id: segment_id.to_owned(),
                    start,
                    end,
                },
                masked_preview: mask_preview(raw),
                fingerprint: fingerprint(hmac_key, raw.as_bytes())?,
                explanation: rule.explanation.clone(),
                remediation: rule.remediation.clone(),
            },
            action: rule.action,
        });
    }
    Ok(())
}

fn contains_zero_width(text: &str) -> bool {
    text.chars().any(is_zero_width)
}

fn is_zero_width(character: char) -> bool {
    matches!(
        character,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'
    )
}

fn remove_zero_width(text: &str) -> (String, Vec<usize>) {
    let mut output = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len() + 1);
    for (index, character) in text.char_indices() {
        if is_zero_width(character) {
            continue;
        }
        let before = output.len();
        output.push(character);
        map.extend(std::iter::repeat_n(index, output.len() - before));
    }
    map.push(text.len());
    (output, map)
}

fn context_window(text: &str, start: usize, end: usize) -> &str {
    let mut window_start = start.saturating_sub(96);
    while window_start < start && !text.is_char_boundary(window_start) {
        window_start += 1;
    }
    let mut window_end = (end + 96).min(text.len());
    while window_end > end && !text.is_char_boundary(window_end) {
        window_end -= 1;
    }
    &text[window_start..window_end]
}

fn mask_preview(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() < 6 {
        return "*".repeat(chars.len().max(3));
    }
    format!(
        "{}{}…{}{}",
        chars[0],
        chars[1],
        chars[chars.len() - 2],
        chars[chars.len() - 1]
    )
}

fn fingerprint(key: &[u8], value: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|error| error.to_string())?;
    mac.update(value);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn is_suppressed(finding: &InternalFinding, envelope: &Envelope, policy: &Policy) -> bool {
    policy.suppressions.iter().any(|suppression| {
        if suppression
            .expires_at
            .as_ref()
            .zip(policy.now.as_ref())
            .is_some_and(|(expiry, now)| expiry <= now)
        {
            return false;
        }
        if suppression
            .rule_id
            .as_ref()
            .is_some_and(|rule| rule != &finding.public.rule_id)
        {
            return false;
        }
        if suppression
            .fingerprint
            .as_ref()
            .is_some_and(|fingerprint| fingerprint != &finding.public.fingerprint)
        {
            return false;
        }
        if suppression.source_pattern.as_ref().is_some_and(|pattern| {
            !envelope
                .source
                .name
                .as_ref()
                .is_some_and(|source| wildcard_match(pattern, source))
        }) {
            return false;
        }
        if suppression.destination.as_ref().is_some_and(|expected| {
            envelope
                .destination
                .as_ref()
                .and_then(|destination| destination.domain.as_ref())
                != Some(expected)
        }) {
            return false;
        }
        true
    })
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let escaped = regex::escape(pattern)
        .replace(r"\*\*", ".*")
        .replace(r"\*", "[^/]*");
    Regex::new(&format!("^{escaped}$")).is_ok_and(|regex| regex.is_match(value))
}

fn transform(envelope: &Envelope, findings: &[InternalFinding]) -> Envelope {
    let mut transformed = envelope.clone();
    let mut placeholders: HashMap<String, String> = HashMap::new();
    let mut counters: HashMap<String, usize> = HashMap::new();

    for segment in &mut transformed.segments {
        let mut segment_findings = findings
            .iter()
            .filter(|finding| {
                finding.public.location.segment_id == segment.id
                    && finding.public.location.start < finding.public.location.end
            })
            .collect::<Vec<_>>();
        segment_findings.sort_by_key(|finding| std::cmp::Reverse(finding.public.location.start));

        let mut replaced_until = segment.text.len();
        for finding in segment_findings {
            let start = finding.public.location.start;
            let end = finding.public.location.end;
            if end > replaced_until || end > segment.text.len() {
                continue;
            }
            let placeholder = placeholders
                .entry(finding.public.fingerprint.clone())
                .or_insert_with(|| {
                    let counter = counters.entry(finding.public.category.clone()).or_default();
                    *counter += 1;
                    format!(
                        "[REDACTED:{}:{}]",
                        finding.public.category.to_ascii_uppercase(),
                        counter
                    )
                })
                .clone();
            let raw = &segment.text[start..end];
            let replacement = if envelope.media_type.contains("json")
                && raw.chars().all(|character| character.is_ascii_digit())
            {
                format!("\"{placeholder}\"")
            } else {
                placeholder
            };
            segment.text.replace_range(start..end, &replacement);
            replaced_until = start;
        }
    }
    transformed
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::model::{Confidence, RulePackManifest, Segment, Severity, Source};

    fn pack() -> RulePack {
        RulePack {
            manifest: RulePackManifest {
                api_version: 1,
                id: "test".to_owned(),
                version: "1.0.0".to_owned(),
                min_engine_version: "0.1.0-alpha.0".to_owned(),
                license: "CC0-1.0".to_owned(),
                locales: vec!["en".to_owned()],
            },
            rules: vec![Rule {
                id: "test.token".to_owned(),
                kind: "text".to_owned(),
                pattern: r"tok_[A-Za-z0-9]{12}".to_owned(),
                category: "credential".to_owned(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                action: Action::Block,
                explanation: "Synthetic token".to_owned(),
                remediation: "Remove it".to_owned(),
                validator: None,
                context: Vec::new(),
                negative_context: Vec::new(),
                requires_context: false,
                min_entropy: None,
                fixtures: None,
            }],
        }
    }

    fn envelope(text: &str) -> Envelope {
        Envelope {
            direction: "to_model".to_owned(),
            source: Source {
                kind: "prompt".to_owned(),
                name: None,
                trust: "trusted".to_owned(),
            },
            destination: None,
            media_type: "text/plain".to_owned(),
            segments: vec![Segment {
                id: "prompt".to_owned(),
                text: text.to_owned(),
                json_path: None,
            }],
        }
    }

    #[test]
    fn never_returns_raw_match() {
        let raw = "tok_abcdefghijkl";
        let decision = scan_envelope(
            &envelope(raw),
            &Policy::default(),
            &[pack()],
            b"0123456789abcdef",
        )
        .expect("scan should succeed");
        let serialized = serde_json::to_string(&decision).expect("serialize");
        assert!(!serialized.contains(raw));
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn redacts_repeated_values_with_stable_placeholder() {
        let policy = Policy {
            redact: true,
            ..Policy::default()
        };
        let decision = scan_envelope(
            &envelope("tok_abcdefghijkl and tok_abcdefghijkl"),
            &policy,
            &[pack()],
            b"0123456789abcdef",
        )
        .expect("scan should succeed");
        let transformed = &decision.transformed.expect("transformed").segments[0].text;
        assert_eq!(
            transformed,
            "[REDACTED:CREDENTIAL:1] and [REDACTED:CREDENTIAL:1]"
        );
    }

    #[test]
    fn detects_zero_width_obfuscation() {
        let decision = scan_envelope(
            &envelope("tok_abcd\u{200b}efghijkl"),
            &Policy::default(),
            &[pack()],
            b"0123456789abcdef",
        )
        .expect("scan should succeed");
        assert_eq!(decision.findings.len(), 1);
    }
}
