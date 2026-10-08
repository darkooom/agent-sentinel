//! Generic JSON protocol for harnesses sentinel has no dedicated adapter for.
//!
//! Input: one action object or an array of them.
//!
//! ```json
//! {"kind": "shell", "command": "git push -f", "cwd": "/repo", "agent": "my-agent"}
//! ```
//!
//! Output: always a JSON object on stdout with `decision`, `reason`, `rule`,
//! `risk` and `findings`. Exit code 0 = allow, 1 = deny (also used for
//! errors), 3 = confirm. The caller is responsible for asking its user
//! when the decision is `confirm`.

use anyhow::{bail, Context, Result};
use sentinel_audit::Outcome;
use sentinel_core::Action;
use sentinel_policy::Verdict;
use serde_json::{json, Value};

use super::{AgentAdapter, HookRequest, HookResponse, Verdicts};

pub struct Generic;

pub fn exit_code(verdict: Verdict) -> i32 {
    match verdict {
        Verdict::Allow => 0,
        Verdict::Deny => 1,
        Verdict::Confirm => 3,
    }
}

impl AgentAdapter for Generic {
    fn id(&self) -> &'static str {
        "generic"
    }

    fn parse(&self, input: &str) -> Result<HookRequest> {
        let value: Value = serde_json::from_str(input).context("input is not JSON")?;
        let items = match value {
            Value::Array(items) => items,
            obj @ Value::Object(_) => vec![obj],
            _ => bail!("expected an action object or an array of actions"),
        };
        let cwd_default = std::env::current_dir().context("no working directory")?;
        let mut actions = Vec::new();
        for mut item in items {
            if let Some(obj) = item.as_object_mut() {
                obj.entry("cwd").or_insert_with(|| json!(cwd_default));
                obj.entry("agent").or_insert_with(|| json!("generic"));
            }
            let action: Action = serde_json::from_value(item)
                .context("invalid action (see docs/integrations.md)")?;
            let complete = match action.kind {
                sentinel_core::ActionKind::Shell => action.command.is_some(),
                sentinel_core::ActionKind::FileRead | sentinel_core::ActionKind::FileWrite => {
                    action.path.is_some()
                }
                sentinel_core::ActionKind::Network => action.url.is_some(),
                sentinel_core::ActionKind::Tool => action.tool.is_some(),
            };
            if !complete {
                bail!(
                    "{} action is missing its target field",
                    action.kind.as_str()
                );
            }
            actions.push(action);
        }
        Ok(HookRequest {
            actions,
            policy_dir: None,
        })
    }

    fn respond(&self, result: &Verdicts) -> HookResponse {
        let body = json!({
            "decision": result.verdict,
            "reason": result.reason,
            "rule": result.rule,
            "risk": result.risk,
            "findings": result.findings,
        });
        HookResponse {
            stdout: Some(body.to_string()),
            stderr: None,
            exit_code: exit_code(result.verdict),
        }
    }

    fn respond_error(&self, error: &str) -> HookResponse {
        let body =
            json!({ "decision": "deny", "reason": format!("error: {error}"), "error": true });
        HookResponse {
            stdout: Some(body.to_string()),
            stderr: None,
            exit_code: 1,
        }
    }

    fn confirm_outcome(&self) -> Outcome {
        Outcome::Asked
    }
}
