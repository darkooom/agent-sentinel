//! Secret detection.
//!
//! Three independent signals:
//!
//! * [`SecretDetector`]s scan text for credentials: provider token formats
//!   (`sk-ant-…`, `AKIA…`, `ghp_…`), private key blocks, URLs with embedded
//!   passwords, and `NAME=value` assignments whose name is sensitive and whose
//!   value is not a placeholder.
//! * [`is_sensitive_name`] recognizes variable names that hold credentials by
//!   their parts (`STRIPE_SECRET_KEY` → `SECRET`), not by a fixed list.
//! * [`classify_path`] recognizes files and directories that conventionally
//!   hold credentials (`.env`, `~/.ssh/id_ed25519`, `~/.aws/credentials`).
//!
//! Matches carry labels and byte ranges, never copies of the secret, so they
//! can be reported and redacted without being leaked.

mod detectors;
mod names;
mod paths;

use std::sync::LazyLock;

pub use detectors::{AssignmentDetector, CliCredentialDetector, TokenDetector};
pub use names::is_sensitive_name;
pub use paths::{classify_path, SecretPath};

/// A credential found in text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
    /// Detector that found it.
    pub detector: &'static str,
    /// What was found: a variable name (`DATABASE_URL`) or a kind
    /// (`Anthropic API key`). Safe to display.
    pub label: String,
    /// Byte range of the secret value in the scanned text.
    pub start: usize,
    pub end: usize,
}

/// A source of secret matches. Implement this to add detectors.
pub trait SecretDetector: Send + Sync {
    /// Stable identifier, e.g. `token`.
    fn id(&self) -> &'static str;
    fn scan(&self, text: &str, out: &mut Vec<SecretMatch>);
}

/// A set of detectors applied together.
pub struct SecretScanner {
    detectors: Vec<Box<dyn SecretDetector>>,
}

impl SecretScanner {
    pub fn new(detectors: Vec<Box<dyn SecretDetector>>) -> Self {
        SecretScanner { detectors }
    }

    /// The built-in detector set.
    pub fn builtin() -> &'static SecretScanner {
        static SCANNER: LazyLock<SecretScanner> = LazyLock::new(|| {
            // Assignments first: `STRIPE_SECRET_KEY=sk_live_…` is reported by
            // its variable name, which says more than the token format.
            SecretScanner::new(vec![
                Box::new(AssignmentDetector),
                Box::new(TokenDetector::builtin()),
                Box::new(CliCredentialDetector::new()),
            ])
        });
        &SCANNER
    }

    /// All non-overlapping matches, ordered by position. When matches
    /// overlap, the earlier detector wins.
    pub fn scan(&self, text: &str) -> Vec<SecretMatch> {
        let mut found = Vec::new();
        for (rank, detector) in self.detectors.iter().enumerate() {
            let mut out = Vec::new();
            detector.scan(text, &mut out);
            found.extend(out.into_iter().map(|m| (rank, m)));
        }
        found.sort_by_key(|(rank, m)| (m.start, *rank, std::cmp::Reverse(m.end)));
        let mut accepted: Vec<(usize, SecretMatch)> = Vec::new();
        for (rank, m) in found {
            if let Some(pos) = accepted
                .iter()
                .position(|(_, a)| m.start < a.end && a.start < m.end)
            {
                // Keep the higher-priority detector; prefer the wider span on ties.
                let (arank, a) = &accepted[pos];
                if rank < *arank || (rank == *arank && m.end - m.start > a.end - a.start) {
                    accepted[pos] = (rank, m);
                }
                continue;
            }
            accepted.push((rank, m));
        }
        let mut matches: Vec<SecretMatch> = accepted.into_iter().map(|(_, m)| m).collect();
        matches.sort_by_key(|m| m.start);
        matches
    }

    /// Distinct labels of all matches, in order of first appearance.
    pub fn labels(&self, text: &str) -> Vec<String> {
        let mut labels: Vec<String> = Vec::new();
        for m in self.scan(text) {
            if !labels.contains(&m.label) {
                labels.push(m.label);
            }
        }
        labels
    }

    /// Replace every secret value with `[REDACTED]`.
    pub fn redact(&self, text: &str) -> String {
        let matches = self.scan(text);
        if matches.is_empty() {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for m in matches {
            if m.start < last {
                continue;
            }
            out.push_str(&text[last..m.start]);
            out.push_str("[REDACTED]");
            last = m.end;
        }
        out.push_str(&text[last..]);
        out
    }
}

/// Redact secrets with the built-in scanner.
pub fn redact(text: &str) -> String {
    SecretScanner::builtin().redact(text)
}

#[cfg(test)]
mod tests;
