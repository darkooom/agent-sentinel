//! The YAML policy file format. Unknown keys are errors: a misspelled
//! matcher must never silently widen a rule.

use sentinel_core::{ActionKind, Risk};
use serde::Deserialize;

use crate::Verdict;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T: Clone> OneOrMany<T> {
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            OneOrMany::One(v) => vec![v.clone()],
            OneOrMany::Many(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub version: u32,
    #[serde(default)]
    pub default: Option<Verdict>,
    #[serde(default)]
    pub protected_branches: Option<Vec<String>>,
    #[serde(default)]
    pub network: Option<NetworkSpec>,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
    #[serde(default)]
    pub tests: Vec<TestSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSpec {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    /// Decision for hosts on neither list.
    #[serde(default = "confirm")]
    pub unknown: Verdict,
}

fn confirm() -> Verdict {
    Verdict::Confirm
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub name: String,
    #[serde(rename = "match")]
    pub matcher: MatchSpec,
    pub action: Verdict,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Conditions of a rule. Every present condition must hold; a list inside a
/// condition means "any of these".
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    pub kind: Option<OneOrMany<ActionKind>>,
    pub agent: Option<OneOrMany<String>>,
    pub tool: Option<OneOrMany<String>>,
    pub command_equals: Option<OneOrMany<String>>,
    pub command_prefix: Option<OneOrMany<String>>,
    pub command_contains: Option<OneOrMany<String>>,
    pub command_regex: Option<OneOrMany<String>>,
    pub executable: Option<OneOrMany<String>>,
    pub path: Option<OneOrMany<String>>,
    pub extension: Option<OneOrMany<String>>,
    pub git: Option<OneOrMany<String>>,
    pub host: Option<OneOrMany<String>>,
    pub env: Option<OneOrMany<String>>,
    pub finding: Option<OneOrMany<String>>,
    pub risk: Option<OneOrMany<Risk>>,
    pub min_risk: Option<Risk>,
    pub cwd: Option<OneOrMany<String>>,
}

/// An expectation checked by `sentinel policy test`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestSpec {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub read: Option<String>,
    #[serde(default)]
    pub write: Option<String>,
    #[serde(default)]
    pub fetch: Option<String>,
    pub expect: Verdict,
}
