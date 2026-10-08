use regex::Regex;

use super::{is_sensitive_name, SecretDetector, SecretMatch};

/// Provider token formats. Each pattern's first capture group (or the whole
/// match) is the secret.
pub struct TokenDetector {
    patterns: Vec<(&'static str, Regex)>,
}

impl TokenDetector {
    pub fn new(patterns: Vec<(&'static str, Regex)>) -> Self {
        TokenDetector { patterns }
    }

    pub fn builtin() -> Self {
        let table: &[(&str, &str)] = &[
            (
                "Private key",
                r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\z)",
            ),
            (
                "Anthropic API key",
                r"\bsk-ant-[a-z0-9]+-[A-Za-z0-9_\-]{20,}",
            ),
            (
                "OpenAI API key",
                r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}",
            ),
            (
                "AWS access key ID",
                r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
            ),
            (
                "GitHub token",
                r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
            ),
            ("GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20,}"),
            (
                "Stripe secret key",
                r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
            ),
            ("Slack token", r"\bxox[abposr]-[A-Za-z0-9\-]{10,}"),
            (
                "Slack webhook",
                r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+",
            ),
            ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
            ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
            ("Hugging Face token", r"\bhf_[A-Za-z0-9]{34,}\b"),
            (
                "SendGrid API key",
                r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
            ),
            (
                "JSON Web Token",
                r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
            ),
            (
                "Database URL with credentials",
                r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://[^\s:/@'\x22]+:[^\s@/'\x22]+@[^\s'\x22]+",
            ),
        ];
        TokenDetector::new(
            table
                .iter()
                .map(|(label, pattern)| {
                    (*label, Regex::new(pattern).expect("valid builtin pattern"))
                })
                .collect(),
        )
    }
}

impl SecretDetector for TokenDetector {
    fn id(&self) -> &'static str {
        "token"
    }

    fn scan(&self, text: &str, out: &mut Vec<SecretMatch>) {
        for (label, re) in &self.patterns {
            for caps in re.captures_iter(text) {
                let m = caps.get(1).or_else(|| caps.get(0)).expect("group 0");
                out.push(SecretMatch {
                    detector: self.id(),
                    label: (*label).to_string(),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
    }
}

/// `NAME=value`, `name: value` and `"name": "value"` where the name is
/// sensitive and the value looks real. Covers dotenv, shell, YAML, TOML and
/// JSON. The label is the variable name.
pub struct AssignmentDetector;

fn line_assignment() -> &'static Regex {
    static RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?m)^[ \t]*(?:export[ \t]+|set[ \t]+|const[ \t]+|let[ \t]+|var[ \t]+)?([A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*(?::=|=|:)[ \t]*([^\r\n]*)")
            .expect("valid regex")
    });
    &RE
}

fn json_assignment() -> &'static Regex {
    static RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r#""([A-Za-z_][A-Za-z0-9_.\-]*)"[ \t]*:[ \t]*"((?:[^"\\\r\n]|\\.)*)""#)
            .expect("valid regex")
    });
    &RE
}

impl SecretDetector for AssignmentDetector {
    fn id(&self) -> &'static str {
        "assignment"
    }

    fn scan(&self, text: &str, out: &mut Vec<SecretMatch>) {
        for caps in line_assignment().captures_iter(text) {
            let (Some(name), Some(raw)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            if !is_sensitive_name(name.as_str()) {
                continue;
            }
            if let Some((start, end)) = value_span(raw.as_str()) {
                let value = &raw.as_str()[start..end];
                if !is_placeholder(value) {
                    out.push(SecretMatch {
                        detector: self.id(),
                        label: name.as_str().to_string(),
                        start: raw.start() + start,
                        end: raw.start() + end,
                    });
                }
            }
        }
        for caps in json_assignment().captures_iter(text) {
            let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            if is_sensitive_name(name.as_str()) && !is_placeholder(value.as_str()) {
                out.push(SecretMatch {
                    detector: self.id(),
                    label: name.as_str().to_string(),
                    start: value.start(),
                    end: value.end(),
                });
            }
        }
    }
}

/// Locate the literal value in the right-hand side of an assignment.
/// Returns `None` when the right-hand side is an expression, not a literal.
fn value_span(raw: &str) -> Option<(usize, usize)> {
    let trimmed = raw.trim_end().trim_end_matches([',', ';']);
    let first = trimmed.chars().next()?;
    if first == '"' || first == '\'' || first == '`' {
        let close = trimmed[1..].find(first)? + 1;
        return Some((1, close));
    }
    // Unquoted: up to an inline comment.
    let end = trimmed.find(" #").unwrap_or(trimmed.len());
    let value = trimmed[..end].trim_end();
    if value.is_empty() || value.contains(['(', ')', '[', ']', '{', '}', ' ']) {
        return None;
    }
    // Dotted identifiers (`config.password`) and short bare words are code,
    // not credentials.
    let identifier = |s: &str| {
        s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if value.contains('.') && value.split('.').all(identifier) {
        return None;
    }
    if value.len() < 16 && value.chars().all(|c| c.is_ascii_alphabetic() || c == '_') {
        return None;
    }
    Some((0, value.len()))
}

fn is_placeholder(value: &str) -> bool {
    let v = value.trim();
    if v.chars().count() < 4 {
        return true;
    }
    let lower = v.to_ascii_lowercase();
    if v.starts_with('$') || v.starts_with('<') || v.starts_with("{{") || v.starts_with("%(") {
        return true;
    }
    const MARKERS: &[&str] = &[
        "your",
        "changeme",
        "change_me",
        "change-me",
        "example",
        "placeholder",
        "dummy",
        "xxxx",
        "todo",
        "replace",
        "insert",
        "redacted",
        "...",
        "***",
        "fake",
        "sample",
    ];
    if MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    const EXACT: &[&str] = &[
        "null",
        "none",
        "nil",
        "true",
        "false",
        "undefined",
        "secret",
        "password",
        "empty",
    ];
    if EXACT.contains(&lower.as_str()) {
        return true;
    }
    let mut chars = v.chars();
    let first = chars.next();
    chars.all(|c| Some(c) == first)
}

/// Credentials passed on a command line: authorization headers, password
/// flags, `user:password@` in URLs.
pub struct CliCredentialDetector {
    patterns: Vec<(&'static str, Regex)>,
}

impl CliCredentialDetector {
    pub fn new() -> Self {
        let table: &[(&str, &str)] = &[
            (
                "Authorization header",
                r"(?i)\bauthorization:[ \t]*(?:bearer|basic|token|bot)[ \t]+([^\s'\x22]{8,})",
            ),
            (
                "API key header",
                r"(?i)\b(?:x-api-key|api-key|x-auth-token|private-token):[ \t]*([^\s'\x22]{8,})",
            ),
            (
                "Password argument",
                r"(?i)(?:^|\s)--?(?:password|passwd|token|api-key|apikey|api-token|secret|access-token|auth-token)(?:=|[ \t]+)([^\s'\x22-][^\s'\x22]{3,})",
            ),
            (
                "Credentials argument",
                r"(?:^|\s)(?:-u|--user)(?:=|[ \t]+)[^\s:'\x22]+:([^\s'\x22]{3,})",
            ),
            (
                "Password in URL",
                r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@'\x22]+:([^\s/@'\x22]{3,})@",
            ),
        ];
        CliCredentialDetector {
            patterns: table
                .iter()
                .map(|(label, pattern)| {
                    (*label, Regex::new(pattern).expect("valid builtin pattern"))
                })
                .collect(),
        }
    }
}

impl Default for CliCredentialDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector for CliCredentialDetector {
    fn id(&self) -> &'static str {
        "cli"
    }

    fn scan(&self, text: &str, out: &mut Vec<SecretMatch>) {
        for (label, re) in &self.patterns {
            for caps in re.captures_iter(text) {
                let Some(m) = caps.get(1) else { continue };
                if is_placeholder(m.as_str()) {
                    continue;
                }
                out.push(SecretMatch {
                    detector: self.id(),
                    label: (*label).to_string(),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
    }
}
