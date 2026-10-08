//! Agent adapters: translate an agent's hook protocol to actions and back.
//!
//! An adapter only parses and renders. Evaluation, auditing and the
//! combination of multiple actions are shared in [`run_hook`], so every
//! agent gets the same policy semantics.

mod claude;
mod codex;
pub mod generic;

use std::path::PathBuf;

use anyhow::Result;
use sentinel_audit::Outcome;
use sentinel_core::{Action, Finding, Risk};
use sentinel_policy::Verdict;

pub use claude::ClaudeCode;
pub use codex::Codex;
pub use generic::Generic;

use crate::Engine;

/// What an agent asked for, normalized.
#[derive(Debug, Default)]
pub struct HookRequest {
    /// Zero or more actions. Zero means "nothing sentinel inspects".
    pub actions: Vec<Action>,
    /// Directory to discover the policy from (project root if the agent
    /// provides one, otherwise the working directory).
    pub policy_dir: Option<PathBuf>,
}

/// The combined result for all actions in a request.
#[derive(Debug, Clone)]
pub struct Verdicts {
    pub verdict: Verdict,
    pub reason: String,
    pub rule: Option<String>,
    pub risk: Risk,
    pub findings: Vec<Finding>,
}

/// What to print and how to exit.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HookResponse {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: i32,
}

pub trait AgentAdapter {
    /// Stable name recorded in audit events.
    fn id(&self) -> &'static str;

    /// Parse the agent's payload.
    fn parse(&self, input: &str) -> Result<HookRequest>;

    /// Render a decision in the agent's protocol.
    fn respond(&self, result: &Verdicts) -> HookResponse;

    /// Render a failure. Must never let the action through silently.
    fn respond_error(&self, error: &str) -> HookResponse;

    /// Audit outcome for a `confirm` verdict: whether the agent can ask its
    /// user (`Asked`) or the adapter had to deny (`Denied`).
    fn confirm_outcome(&self) -> Outcome;
}

pub fn adapter(name: &str) -> Option<Box<dyn AgentAdapter>> {
    match name {
        "claude-code" | "claude" => Some(Box::new(ClaudeCode)),
        "codex" => Some(Box::new(Codex)),
        "generic" => Some(Box::new(Generic)),
        _ => None,
    }
}

pub const ADAPTERS: &[&str] = &["claude-code", "codex", "generic"];

/// Parse, evaluate every action, audit, and render one response. Any error
/// or panic is rendered through [`AgentAdapter::respond_error`].
pub fn run_hook(
    adapter: &dyn AgentAdapter,
    input: &str,
    policy_override: Option<&std::path::Path>,
) -> HookResponse {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        evaluate_hook(adapter, input, policy_override)
    }));
    match result {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => adapter.respond_error(&format!("{e:#}")),
        Err(_) => adapter.respond_error("internal error while evaluating the action"),
    }
}

fn evaluate_hook(
    adapter: &dyn AgentAdapter,
    input: &str,
    policy_override: Option<&std::path::Path>,
) -> Result<HookResponse> {
    let request = adapter.parse(input)?;
    if request.actions.is_empty() {
        return Ok(adapter.respond(&Verdicts {
            verdict: Verdict::Allow,
            reason: "nothing to inspect".into(),
            rule: None,
            risk: Risk::Low,
            findings: Vec::new(),
        }));
    }
    let dir = match &request.policy_dir {
        Some(d) => d.clone(),
        None => request.actions[0].cwd.clone(),
    };
    let engine = Engine::load(policy_override, &dir)?;
    let mut combined: Option<Verdicts> = None;
    for action in &request.actions {
        let eval = engine.evaluate(action);
        let outcome = match eval.decision.verdict {
            Verdict::Allow => Outcome::Allowed,
            Verdict::Deny => Outcome::Denied,
            Verdict::Confirm => adapter.confirm_outcome(),
        };
        if let Err(e) = engine.record(action, &eval, outcome) {
            eprintln!("agent-sentinel: could not write audit log: {e:#}");
        }
        let this = Verdicts {
            verdict: eval.decision.verdict,
            reason: eval.decision.reason.clone(),
            rule: eval.decision.rule.clone(),
            risk: eval.decision.risk,
            findings: eval.analysis.findings.clone(),
        };
        combined = Some(match combined {
            Some(prev) if prev.verdict >= this.verdict => prev,
            _ => this,
        });
    }
    Ok(adapter.respond(&combined.expect("at least one action")))
}

/// One-line reason shown to the user or the agent.
pub(crate) fn describe(result: &Verdicts) -> String {
    let mut text = format!("agent-sentinel: {}", result.reason);
    if let Some(top) = result.findings.first() {
        if top.message != result.reason {
            text.push_str(&format!(" ({})", top.message));
        }
    }
    if let Some(rule) = &result.rule {
        text.push_str(&format!(" [rule: {rule}]"));
    }
    sentinel_core::display::sanitize_line(&sentinel_core::secrets::redact(&text))
}

#[cfg(test)]
mod tests;
