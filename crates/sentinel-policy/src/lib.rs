//! Policy language and evaluation.
//!
//! A policy is a list of rules. Each rule has conditions (`match`) and a
//! verdict (`action`). Evaluation collects the verdicts of every matching
//! rule plus the network section and returns the most restrictive one:
//! **deny > confirm > allow > default**. Rule order does not matter.

mod matcher;
mod schema;

use std::fmt;
use std::path::{Path, PathBuf};

use sentinel_core::{analyze, Action, Analysis, AnalysisContext, Risk};
use serde::{Deserialize, Serialize};

pub use matcher::{host_matches, Mode};
pub use schema::{MatchSpec, NetworkSpec, PolicyFile, RuleSpec, TestSpec};

use matcher::{Matcher, Subject};

/// The built-in policy, also written by `sentinel init`.
pub const DEFAULT_POLICY: &str = include_str!("default.yml");

/// What happens to an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    #[serde(alias = "ask")]
    Confirm,
    #[serde(alias = "block")]
    Deny,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Confirm => "confirm",
            Verdict::Deny => "deny",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("{0}")]
    Parse(String),
    #[error("{context}: {message}")]
    Invalid { context: String, message: String },
}

impl PolicyError {
    fn invalid(context: impl Into<String>, message: impl Into<String>) -> Self {
        PolicyError::Invalid {
            context: context.into(),
            message: message.into(),
        }
    }
}

/// A rule that matched during evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleMatch {
    pub rule: String,
    pub verdict: Verdict,
}

/// The outcome of evaluating an action against a policy.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub verdict: Verdict,
    /// Deciding rule; `network` for the network section; `None` when the
    /// default applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub reason: String,
    pub risk: Risk,
    /// Every rule that matched, most restrictive first.
    pub matched: Vec<RuleMatch>,
}

struct Rule {
    name: String,
    verdict: Verdict,
    reason: Option<String>,
    matcher: Matcher,
}

struct Network {
    allow: Vec<String>,
    deny: Vec<String>,
    unknown: Verdict,
}

/// Where a policy came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    Builtin,
    File(PathBuf),
}

impl fmt::Display for PolicySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicySource::Builtin => f.write_str("built-in default"),
            PolicySource::File(p) => write!(f, "{}", p.display()),
        }
    }
}

/// A validated, compiled policy.
pub struct Policy {
    pub source: PolicySource,
    pub default: Verdict,
    pub protected_branches: Vec<String>,
    rules: Vec<Rule>,
    network: Option<Network>,
    pub tests: Vec<TestSpec>,
}

impl Policy {
    pub fn builtin() -> Policy {
        Policy::from_yaml(DEFAULT_POLICY, PolicySource::Builtin).expect("built-in policy is valid")
    }

    pub fn from_yaml(text: &str, source: PolicySource) -> Result<Policy, PolicyError> {
        let file: PolicyFile =
            serde_yaml_ng::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))?;
        Policy::compile(file, source)
    }

    pub fn compile(file: PolicyFile, source: PolicySource) -> Result<Policy, PolicyError> {
        if file.version != 1 {
            return Err(PolicyError::invalid(
                "version",
                format!("unsupported policy version {} (expected 1)", file.version),
            ));
        }
        let mut rules = Vec::new();
        for spec in &file.rules {
            let name = spec.name.trim();
            if name.is_empty() {
                return Err(PolicyError::invalid(
                    "rules",
                    "every rule needs a non-empty `name`",
                ));
            }
            if rules.iter().any(|r: &Rule| r.name == name) {
                return Err(PolicyError::invalid(
                    format!("rule `{name}`"),
                    "duplicate rule name",
                ));
            }
            rules.push(Rule {
                name: name.to_string(),
                verdict: spec.action,
                reason: spec.reason.clone().filter(|r| !r.trim().is_empty()),
                matcher: Matcher::compile(&spec.matcher, &format!("rule `{name}`"))?,
            });
        }
        let protected_branches = file
            .protected_branches
            .unwrap_or_else(|| vec!["main".into(), "master".into()]);
        for b in &protected_branches {
            matcher::validate_glob(b, "protected_branches")?;
        }
        let network = match file.network {
            Some(n) => {
                for h in n.allow.iter().chain(&n.deny) {
                    if h.contains("://") || h.contains('/') {
                        return Err(PolicyError::invalid(
                            "network",
                            format!(
                                "`{h}` must be a hostname like `example.com` or `*.example.com`"
                            ),
                        ));
                    }
                }
                Some(Network {
                    allow: n.allow.iter().map(|h| h.to_ascii_lowercase()).collect(),
                    deny: n.deny.iter().map(|h| h.to_ascii_lowercase()).collect(),
                    unknown: n.unknown,
                })
            }
            None => None,
        };
        for (i, t) in file.tests.iter().enumerate() {
            let targets = [&t.command, &t.read, &t.write, &t.fetch]
                .iter()
                .filter(|v| v.is_some())
                .count();
            if targets != 1 {
                return Err(PolicyError::invalid(
                    format!("tests[{i}]"),
                    "set exactly one of `command`, `read`, `write`, `fetch`",
                ));
            }
        }
        Ok(Policy {
            source,
            default: file.default.unwrap_or(Verdict::Allow),
            protected_branches,
            rules,
            network,
            tests: file.tests,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn network_unknown(&self) -> Option<Verdict> {
        self.network.as_ref().map(|n| n.unknown)
    }

    /// Decide what happens to an analyzed action. `project_root` anchors
    /// relative path patterns (falls back to the action's cwd).
    pub fn evaluate(
        &self,
        action: &Action,
        analysis: &Analysis,
        project_root: Option<&Path>,
    ) -> Decision {
        let subject = Subject {
            action,
            analysis,
            base: project_root.unwrap_or(&action.cwd),
        };
        // (verdict, rule name, reason)
        let mut hits: Vec<(Verdict, String, String)> = Vec::new();
        for rule in &self.rules {
            let mode = if rule.verdict == Verdict::Allow {
                Mode::All
            } else {
                Mode::Any
            };
            if rule.matcher.matches(&subject, mode) {
                let reason = rule
                    .reason
                    .clone()
                    .or_else(|| rule.matcher.evidence(analysis).map(str::to_string))
                    .or_else(|| analysis.findings.first().map(|f| f.message.clone()))
                    .unwrap_or_else(|| format!("matched rule `{}`", rule.name));
                hits.push((rule.verdict, rule.name.clone(), reason));
            }
        }
        if let Some(net) = &self.network {
            for host in &analysis.facts.hosts {
                let (verdict, reason) = if net.deny.iter().any(|p| host_matches(p, &host.name)) {
                    (
                        Verdict::Deny,
                        format!("{} is on the network deny list", host.name),
                    )
                } else if net.allow.iter().any(|p| host_matches(p, &host.name)) {
                    (
                        Verdict::Allow,
                        format!("{} is on the network allow list", host.name),
                    )
                } else {
                    (
                        net.unknown,
                        format!("{} is not on the network allow list", host.name),
                    )
                };
                hits.push((verdict, "network".into(), reason));
            }
        }
        // Stable sort keeps policy order among equal verdicts.
        hits.sort_by_key(|h| std::cmp::Reverse(h.0));
        let matched: Vec<RuleMatch> = hits
            .iter()
            .map(|(verdict, rule, _)| RuleMatch {
                rule: rule.clone(),
                verdict: *verdict,
            })
            .collect();
        match hits.into_iter().next() {
            Some((verdict, rule, reason)) => Decision {
                verdict,
                rule: Some(rule),
                reason,
                risk: analysis.risk,
                matched,
            },
            None => Decision {
                verdict: self.default,
                rule: None,
                reason: format!("no rule matched; the policy default is {}", self.default),
                risk: analysis.risk,
                matched,
            },
        }
    }

    /// Run the policy's `tests:` section. Files are not inspected, so results
    /// do not depend on the machine running them.
    pub fn run_tests(&self, cwd: &Path, home: Option<PathBuf>) -> Vec<TestOutcome> {
        let ctx = AnalysisContext {
            home,
            project_root: Some(cwd.to_path_buf()),
            protected_branches: self.protected_branches.clone(),
            protected_paths: Vec::new(),
            inspect_files: false,
        };
        self.tests
            .iter()
            .map(|t| {
                let action = if let Some(c) = &t.command {
                    Action::shell(c.clone(), cwd)
                } else if let Some(p) = &t.read {
                    Action::file_read(cwd.join(p).to_string_lossy(), cwd)
                } else if let Some(p) = &t.write {
                    Action::file_write(cwd.join(p).to_string_lossy(), None, cwd)
                } else {
                    Action::network(t.fetch.clone().unwrap_or_default(), cwd)
                };
                let analysis = analyze(&action, &ctx);
                let decision = self.evaluate(&action, &analysis, Some(cwd));
                TestOutcome {
                    target: action.target().to_string(),
                    expected: t.expect,
                    decision,
                }
            })
            .collect()
    }
}

pub struct TestOutcome {
    pub target: String,
    pub expected: Verdict,
    pub decision: Decision,
}

impl TestOutcome {
    pub fn passed(&self) -> bool {
        self.expected == self.decision.verdict
    }
}

#[cfg(test)]
mod tests;
