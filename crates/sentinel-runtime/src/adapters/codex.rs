//! OpenAI Codex CLI `PreToolUse` hook.
//!
//! Protocol (https://developers.openai.com/codex/hooks and the JSON schemas
//! in openai/codex `codex-rs/hooks/schema`): `tool_name` is `Bash` for
//! shell commands and `apply_patch` for file edits; both carry their text
//! in `tool_input.command`. Denials use `hookSpecificOutput.permissionDecision
//! = "deny"`.
//!
//! Codex parses `permissionDecision: "ask"` but does not support it: the
//! hook is marked failed and the tool call proceeds. Non-zero exit codes
//! also proceed. So this adapter fails closed: `confirm` and errors are
//! rendered as `deny`, with a reason telling the user how to proceed.

use std::path::PathBuf;

use anyhow::{Context, Result};
use sentinel_audit::Outcome;
use sentinel_core::shell::quote_argv;
use sentinel_core::Action;
use sentinel_policy::Verdict;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{describe, AgentAdapter, HookRequest, HookResponse, Verdicts};

pub struct Codex;

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

impl AgentAdapter for Codex {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn parse(&self, input: &str) -> Result<HookRequest> {
        let payload: Payload =
            serde_json::from_str(input).context("hook input is not a Codex PreToolUse payload")?;
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
        let tool = payload.tool_name.as_str();
        let command = command_text(&payload.tool_input);
        let mut actions = Vec::new();
        match tool {
            "Bash" | "shell" | "local_shell" | "exec_command" | "unified_exec" => {
                actions.push(Action::shell(
                    command.context("shell call without `command`")?,
                    &cwd,
                ));
            }
            "apply_patch" | "Edit" | "Write" => {
                let patch = command.context("apply_patch call without `command`")?;
                for (path, added) in patch_files(&patch) {
                    actions.push(Action::file_write(path, Some(added), &cwd));
                }
            }
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
            policy_dir: Some(cwd),
        })
    }

    fn respond(&self, result: &Verdicts) -> HookResponse {
        match result.verdict {
            Verdict::Allow => HookResponse::default(),
            Verdict::Deny => deny(&describe(result)),
            Verdict::Confirm => deny(&format!(
                "{} — requires confirmation, and Codex hooks cannot ask. Run it yourself if intended, or relax .sentinel/policy.yml.",
                describe(result)
            )),
        }
    }

    fn respond_error(&self, error: &str) -> HookResponse {
        deny(&format!(
            "agent-sentinel could not evaluate this action ({error}); denied to fail closed"
        ))
    }

    fn confirm_outcome(&self) -> Outcome {
        Outcome::Denied
    }
}

/// `tool_input.command` is documented as a string; accept an argv array too.
fn command_text(input: &Value) -> Option<String> {
    match input.get("command")? {
        Value::String(s) => Some(s.clone()),
        Value::Array(parts) => {
            let argv: Vec<String> = parts
                .iter()
                .filter_map(|p| p.as_str().map(str::to_string))
                .collect();
            // ["bash", "-lc", "script"] → the script is what matters.
            if argv.len() == 3 && argv[1].starts_with('-') && argv[1].contains('c') {
                Some(argv[2].clone())
            } else {
                Some(quote_argv(&argv))
            }
        }
        _ => None,
    }
}

/// Files touched by an `apply_patch` envelope and the lines it adds.
fn patch_files(patch: &str) -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = Vec::new();
    for line in patch.lines() {
        let header = [
            "*** Add File: ",
            "*** Update File: ",
            "*** Delete File: ",
            "*** Move to: ",
        ]
        .iter()
        .find_map(|h| line.strip_prefix(h));
        if let Some(path) = header {
            files.push((path.trim().to_string(), String::new()));
        } else if let (Some(added), Some((_, content))) = (line.strip_prefix('+'), files.last_mut())
        {
            content.push_str(added);
            content.push('\n');
        }
    }
    files
}

fn deny(reason: &str) -> HookResponse {
    let body = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    });
    HookResponse {
        stdout: Some(body.to_string()),
        stderr: None,
        exit_code: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_patch_headers() {
        let patch = "*** Begin Patch\n*** Update File: src/a.rs\n@@\n-old\n+new line\n*** Add File: .env\n+KEY=1\n*** End Patch\n";
        let files = patch_files(patch);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0], ("src/a.rs".to_string(), "new line\n".to_string()));
        assert_eq!(files[1].0, ".env");
    }

    #[test]
    fn command_forms() {
        assert_eq!(
            command_text(&json!({"command": "ls"})).as_deref(),
            Some("ls")
        );
        assert_eq!(
            command_text(&json!({"command": ["bash", "-lc", "rm -rf x"]})).as_deref(),
            Some("rm -rf x")
        );
        assert_eq!(
            command_text(&json!({"command": ["ls", "-la", "a b"]})).as_deref(),
            Some("ls -la 'a b'")
        );
    }
}
