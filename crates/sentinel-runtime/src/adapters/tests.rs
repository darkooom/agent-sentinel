use sentinel_core::{ActionKind, Risk};
use sentinel_policy::Verdict;
use serde_json::{json, Value};

use super::*;

fn verdicts(verdict: Verdict) -> Verdicts {
    Verdicts {
        verdict,
        reason: "Dangerous recursive deletion".into(),
        rule: Some("block-recursive-delete".into()),
        risk: Risk::High,
        findings: Vec::new(),
    }
}

fn stdout_json(r: &HookResponse) -> Value {
    serde_json::from_str(r.stdout.as_deref().expect("stdout")).unwrap()
}

#[test]
fn claude_maps_tools_to_actions() {
    let cases = [
        (
            json!({"tool_name": "Bash", "tool_input": {"command": "rm -rf x", "description": "d"}}),
            ActionKind::Shell,
            "rm -rf x",
        ),
        (
            json!({"tool_name": "Read", "tool_input": {"file_path": "/p/.env"}}),
            ActionKind::FileRead,
            "/p/.env",
        ),
        (
            json!({"tool_name": "Write", "tool_input": {"file_path": "/p/a.rs", "content": "fn main(){}"}}),
            ActionKind::FileWrite,
            "/p/a.rs",
        ),
        (
            json!({"tool_name": "Edit", "tool_input": {"file_path": "/p/a.rs", "old_string": "a", "new_string": "b"}}),
            ActionKind::FileWrite,
            "/p/a.rs",
        ),
        (
            json!({"tool_name": "WebFetch", "tool_input": {"url": "https://x.example.com", "prompt": "p"}}),
            ActionKind::Network,
            "https://x.example.com",
        ),
        (
            json!({"tool_name": "mcp__db__query", "tool_input": {"sql": "select 1"}}),
            ActionKind::Tool,
            "mcp__db__query",
        ),
    ];
    for (mut payload, kind, target) in cases {
        payload["hook_event_name"] = json!("PreToolUse");
        payload["cwd"] = json!("/p");
        payload["session_id"] = json!("s1");
        let req = ClaudeCode.parse(&payload.to_string()).unwrap();
        assert_eq!(req.actions.len(), 1, "{payload}");
        let a = &req.actions[0];
        assert_eq!(a.kind, kind);
        assert_eq!(a.target(), target);
        assert_eq!(a.agent, "claude-code");
        assert_eq!(a.session.as_deref(), Some("s1"));
    }
    let edit = json!({"tool_name": "Edit", "cwd": "/p", "tool_input": {"file_path": "/p/a.rs", "old_string": "a", "new_string": "SECRET"}});
    assert_eq!(
        ClaudeCode.parse(&edit.to_string()).unwrap().actions[0]
            .content
            .as_deref(),
        Some("SECRET")
    );
}

#[test]
fn claude_ignores_listing_tools_and_other_events() {
    let glob = json!({"hook_event_name": "PreToolUse", "cwd": "/p", "tool_name": "Glob", "tool_input": {"pattern": "**/*"}});
    assert!(ClaudeCode
        .parse(&glob.to_string())
        .unwrap()
        .actions
        .is_empty());
    let post = json!({"hook_event_name": "PostToolUse", "cwd": "/p", "tool_name": "Bash", "tool_input": {"command": "ls"}});
    assert!(ClaudeCode
        .parse(&post.to_string())
        .unwrap()
        .actions
        .is_empty());
}

#[test]
fn claude_grep_with_glob_checks_the_glob() {
    let grep = json!({"hook_event_name": "PreToolUse", "cwd": "/p", "tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": "/p", "glob": ".env*"}});
    let req = ClaudeCode.parse(&grep.to_string()).unwrap();
    assert_eq!(req.actions.len(), 2);
    assert_eq!(req.actions[1].path.as_deref(), Some("/p/.env*"));
}

#[test]
fn claude_rejects_malformed_input() {
    assert!(ClaudeCode.parse("not json").is_err());
    assert!(ClaudeCode
        .parse(r#"{"tool_name":"Bash","cwd":"/p","tool_input":{}}"#)
        .is_err());
}

#[test]
fn claude_responses() {
    // Allow: silent, so Claude Code's own permission rules still apply.
    assert_eq!(
        ClaudeCode.respond(&verdicts(Verdict::Allow)),
        HookResponse::default()
    );
    let deny = ClaudeCode.respond(&verdicts(Verdict::Deny));
    assert_eq!(deny.exit_code, 0);
    let v = stdout_json(&deny);
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("block-recursive-delete"));
    let ask = stdout_json(&ClaudeCode.respond(&verdicts(Verdict::Confirm)));
    assert_eq!(ask["hookSpecificOutput"]["permissionDecision"], "ask");
    // Errors never allow.
    let err = ClaudeCode.respond_error("boom");
    assert_eq!(err.exit_code, 0);
    assert_eq!(
        stdout_json(&err)["hookSpecificOutput"]["permissionDecision"],
        "ask"
    );
}

#[test]
fn codex_fails_closed() {
    assert_eq!(
        Codex.respond(&verdicts(Verdict::Allow)),
        HookResponse::default()
    );
    for r in [
        Codex.respond(&verdicts(Verdict::Deny)),
        Codex.respond(&verdicts(Verdict::Confirm)),
        Codex.respond_error("boom"),
    ] {
        assert_eq!(r.exit_code, 0);
        assert_eq!(
            stdout_json(&r)["hookSpecificOutput"]["permissionDecision"],
            "deny"
        );
    }
    let confirm = stdout_json(&Codex.respond(&verdicts(Verdict::Confirm)));
    assert!(confirm["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("cannot ask"));
}

#[test]
fn codex_parses_bash_and_patches() {
    let bash = json!({"hook_event_name": "PreToolUse", "cwd": "/p", "tool_name": "Bash", "tool_input": {"command": "git push -f"}, "session_id": "x", "model": "m", "permission_mode": "default", "tool_use_id": "t", "transcript_path": null, "turn_id": "u"});
    let req = Codex.parse(&bash.to_string()).unwrap();
    assert_eq!(req.actions[0].command.as_deref(), Some("git push -f"));
    assert_eq!(req.actions[0].agent, "codex");
    let patch = json!({"hook_event_name": "PreToolUse", "cwd": "/p", "tool_name": "apply_patch", "tool_input": {"command": "*** Begin Patch\n*** Add File: .sentinel/policy.yml\n+default: allow\n*** End Patch"}});
    let req = Codex.parse(&patch.to_string()).unwrap();
    assert_eq!(req.actions[0].kind, ActionKind::FileWrite);
    assert_eq!(req.actions[0].path.as_deref(), Some(".sentinel/policy.yml"));
}

#[test]
fn generic_protocol() {
    let one = json!({"kind": "shell", "command": "ls", "cwd": "/p", "agent": "bot"});
    let req = Generic.parse(&one.to_string()).unwrap();
    assert_eq!(req.actions[0].agent, "bot");
    let many = json!([{"kind": "file_read", "path": "/p/.env", "cwd": "/p"}, {"kind": "network", "url": "https://x.example.com"}]);
    assert_eq!(Generic.parse(&many.to_string()).unwrap().actions.len(), 2);
    assert!(Generic.parse(r#"{"kind":"shell","cwd":"/p"}"#).is_err());
    assert!(Generic.parse(r#"{"kind":"teleport","cwd":"/p"}"#).is_err());
    let r = Generic.respond(&verdicts(Verdict::Confirm));
    assert_eq!(r.exit_code, 3);
    assert_eq!(stdout_json(&r)["decision"], "confirm");
    assert_eq!(Generic.respond_error("x").exit_code, 1);
}

#[test]
fn reasons_are_sanitized() {
    let mut v = verdicts(Verdict::Deny);
    v.reason = "evil\x1b[2Jreason".into();
    let r = ClaudeCode.respond(&v);
    assert!(!r.stdout.unwrap().contains('\x1b'));
}
