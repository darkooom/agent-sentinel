//! Claude Code `PreToolUse` hook.
//!
//! Protocol (https://code.claude.com/docs/en/hooks): the hook receives JSON
//! on stdin with `tool_name`, `tool_input`, `cwd`, `session_id`; it answers
//! on stdout with `hookSpecificOutput.permissionDecision`.
//!
//! * deny    → `permissionDecision: "deny"`, reason shown to Claude
//! * confirm → `permissionDecision: "ask"`, Claude Code prompts the user
//! * allow   → no output: Claude Code's own permission rules still apply.
//!   Sentinel never grants permissions, it only removes them.
//! * error   → `ask`. Claude Code treats hook crashes and non-zero exits as
//!   "proceed", so errors must be answered, not raised.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use sentinel_audit::Outcome;
use sentinel_core::Action;
use sentinel_policy::Verdict;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{describe, AgentAdapter, HookRequest, HookResponse, Verdicts};

pub struct ClaudeCode;

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    hook_event_name: Option<String>,
    tool_name: String,
    #[serde(default)]
    tool_input: Value,
}

fn str_field<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input.get(key).and_then(Value::as_str)
}

impl AgentAdapter for ClaudeCode {
    fn id(&self) -> &'static str {
        "claude-code"
    }

    fn parse(&self, input: &str) -> Result<HookRequest> {
        let payload: Payload = serde_json::from_str(input)
            .context("hook input is not a Claude Code PreToolUse payload")?;
        if payload
            .hook_event_name
            .as_deref()
            .is_some_and(|e| e != "PreToolUse")
        {
            return Ok(HookRequest::default());
        }
        let cwd = payload
            .cwd
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .context("no working directory")?;
        let project_dir = std::env::var_os("CLAUDE_PROJECT_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        let input = &payload.tool_input;
        let tool = payload.tool_name.as_str();
        let required = |key: &str| -> Result<String> {
            match str_field(input, key) {
                Some(v) => Ok(v.to_string()),
                None => bail!("{tool} call without `{key}`"),
            }
        };
        let mut actions = Vec::new();
        match tool {
            "Bash" | "PowerShell" => actions.push(Action::shell(required("command")?, &cwd)),
            "Read" => actions.push(Action::file_read(required("file_path")?, &cwd)),
            "Write" => actions.push(Action::file_write(
                required("file_path")?,
                str_field(input, "content").map(str::to_string),
                &cwd,
            )),
            "Edit" => actions.push(Action::file_write(
                required("file_path")?,
                str_field(input, "new_string").map(str::to_string),
                &cwd,
            )),
            "MultiEdit" => {
                let content = input.get("edits").and_then(Value::as_array).map(|edits| {
                    edits
                        .iter()
                        .filter_map(|e| str_field(e, "new_string"))
                        .collect::<Vec<_>>()
                        .join("\n")
                });
                actions.push(Action::file_write(required("file_path")?, content, &cwd));
            }
            "NotebookEdit" => {
                let path = str_field(input, "notebook_path")
                    .or_else(|| str_field(input, "path"))
                    .context("NotebookEdit call without a path")?;
                let content = str_field(input, "new_source")
                    .or_else(|| str_field(input, "source"))
                    .map(str::to_string);
                actions.push(Action::file_write(path, content, &cwd));
            }
            "Grep" => {
                let base = str_field(input, "path")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| cwd.clone());
                actions.push(Action::file_read(base.to_string_lossy(), &cwd));
                if let Some(glob) = str_field(input, "glob") {
                    actions.push(Action::file_read(base.join(glob).to_string_lossy(), &cwd));
                }
            }
            "WebFetch" => actions.push(Action::network(required("url")?, &cwd)),
            // Listing names and searching the web expose nothing local.
            "Glob" | "LS" | "WebSearch" | "TodoWrite" => {}
            other => actions.push(Action::tool(other, &cwd)),
        }
        let actions = actions
            .into_iter()
            .map(|a| {
                a.with_agent(self.id())
                    .with_tool(tool)
                    .with_session(payload.session_id.clone())
            })
            .collect();
        Ok(HookRequest {
            actions,
            policy_dir: project_dir.or(Some(cwd)),
        })
    }

    fn respond(&self, result: &Verdicts) -> HookResponse {
        let decision = match result.verdict {
            Verdict::Allow => return HookResponse::default(),
            Verdict::Deny => "deny",
            Verdict::Confirm => "ask",
        };
        output(decision, &describe(result))
    }

    fn respond_error(&self, error: &str) -> HookResponse {
        output("ask", &format!("agent-sentinel could not evaluate this action ({error}); asking instead of allowing"))
    }

    fn confirm_outcome(&self) -> Outcome {
        Outcome::Asked
    }
}

fn output(decision: &str, reason: &str) -> HookResponse {
    let body = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    });
    HookResponse {
        stdout: Some(body.to_string()),
        stderr: None,
        exit_code: 0,
    }
}
