//! End-to-end tests of the `sentinel` binary.
//!
//! Every test gets its own project directory and `SENTINEL_HOME`, and runs
//! with `AI_AGENT=1` so a confirmation can never block waiting for a key on
//! a real terminal (it fails closed instead, which is also what we assert).

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

struct Env {
    project: tempfile::TempDir,
    home: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        let env = Env {
            project: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
        };
        std::fs::create_dir(env.dir().join(".git")).unwrap();
        std::fs::write(
            env.dir().join(".git/HEAD"),
            "ref: refs/heads/feature/login\n",
        )
        .unwrap();
        env
    }

    fn initialized() -> Env {
        let env = Env::new();
        env.cmd().arg("init").assert().success();
        env
    }

    fn dir(&self) -> &Path {
        self.project.path()
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("sentinel").unwrap();
        cmd.current_dir(self.dir())
            .env("SENTINEL_HOME", self.home.path())
            .env("AI_AGENT", "1")
            .env("NO_COLOR", "1")
            .env_remove("CLAUDECODE")
            .env_remove("SENTINEL_POLICY")
            .env_remove("SENTINEL_SESSION")
            .env_remove("CLAUDE_PROJECT_DIR");
        cmd
    }

    fn audit(&self) -> Vec<Value> {
        let text =
            std::fs::read_to_string(self.home.path().join("audit.jsonl")).unwrap_or_default();
        text.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn fixture(&self, name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name);
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        text.replace("{{CWD}}", &self.dir().to_string_lossy())
    }
}

fn hook_decision(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    if text.trim().is_empty() {
        return None;
    }
    let v: Value = serde_json::from_str(text.trim()).expect("hook output is JSON");
    Some(
        v["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap()
            .to_string(),
    )
}

// ------------------------------------------------------------------- init

#[test]
fn init_creates_policy() {
    let env = Env::new();
    env.cmd()
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("created .sentinel/policy.yml"));
    let policy = std::fs::read_to_string(env.dir().join(".sentinel/policy.yml")).unwrap();
    assert!(policy.contains("version: 1"));
    env.cmd()
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
    env.cmd().args(["init", "--force"]).assert().success();
}

#[test]
fn init_registers_claude_code_hook() {
    let env = Env::new();
    env.cmd()
        .args(["init", "--claude-code"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Claude Code hook"));
    let settings: Value = serde_json::from_str(
        &std::fs::read_to_string(env.dir().join(".claude/settings.local.json")).unwrap(),
    )
    .unwrap();
    let command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(command.ends_with("hook claude-code"), "{command}");
    env.cmd()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("✓ hook in"));
}

// -------------------------------------------------------------------- run

#[test]
fn run_blocks_recursive_delete() {
    let env = Env::initialized();
    std::fs::create_dir(env.dir().join("test")).unwrap();
    env.cmd()
        .args(["run", "rm -rf ./test"])
        .assert()
        .code(126)
        .stderr(predicate::str::contains("BLOCKED"))
        .stderr(predicate::str::contains("Dangerous recursive deletion"))
        .stderr(predicate::str::contains("block-recursive-delete"));
    assert!(
        env.dir().join("test").is_dir(),
        "the directory must survive"
    );
    let events = env.audit();
    assert_eq!(events.last().unwrap()["outcome"], "denied");
    assert_eq!(events.last().unwrap()["command"], "rm -rf ./test");
}

#[test]
fn run_blocks_without_a_policy_file() {
    let env = Env::new();
    std::fs::create_dir(env.dir().join("test")).unwrap();
    env.cmd().args(["run", "rm -rf ./test"]).assert().code(126);
    assert!(env.dir().join("test").is_dir());
}

#[test]
fn run_executes_allowed_commands() {
    let env = Env::initialized();
    env.cmd()
        .args(["run", "echo hello && echo world"])
        .assert()
        .success()
        .stdout("hello\nworld\n");
    env.cmd().args(["run", "exit 7"]).assert().code(7);
    // Several arguments are executed directly: no shell interpretation.
    env.cmd()
        .args(["run", "echo", "a;b", "$HOME"])
        .assert()
        .success()
        .stdout("a;b $HOME\n");
    assert_eq!(env.audit().last().unwrap()["outcome"], "allowed");
}

#[test]
fn run_confirm_fails_closed_without_a_human() {
    let env = Env::initialized();
    env.cmd()
        .args(["run", "git push --force origin feature/login"])
        .write_stdin("a\n") // piped input must never count as approval
        .assert()
        .code(126)
        .stderr(predicate::str::contains("CONFIRMATION REQUIRED"))
        .stderr(predicate::str::contains("denied"));
    assert_eq!(env.audit().last().unwrap()["outcome"], "denied_no_terminal");
}

#[test]
fn run_protects_the_policy() {
    let env = Env::initialized();
    let before = std::fs::read_to_string(env.dir().join(".sentinel/policy.yml")).unwrap();
    for cmd in [
        "echo 'default: allow' > .sentinel/policy.yml",
        "rm -rf .sentinel",
        "sed -i.bak 's/deny/allow/' .sentinel/policy.yml",
    ] {
        env.cmd().args(["run", cmd]).assert().code(126);
    }
    assert_eq!(
        std::fs::read_to_string(env.dir().join(".sentinel/policy.yml")).unwrap(),
        before
    );
}

#[test]
fn run_blocks_secret_files_and_names_them() {
    let env = Env::initialized();
    std::fs::write(
        env.dir().join(".env"),
        format!(
            "DATABASE_URL=postgres://app:{}@db:5432/app\nSTRIPE_SECRET_KEY=sk_live_{}\n",
            "hunter2hunter2",
            "4eC39HqLyj".repeat(3)
        ),
    )
    .unwrap();
    let out = env
        .cmd()
        .args(["run", "cat .env"])
        .assert()
        .code(126)
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("DATABASE_URL") && stderr.contains("STRIPE_SECRET_KEY"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("hunter2"),
        "secret values must never be shown"
    );
    assert!(out.stdout.is_empty(), "the file must not be printed");
}

#[test]
fn secrets_are_redacted_everywhere() {
    let env = Env::initialized();
    let token = format!("ghp_{}", "a1B2c3D4e5".repeat(4));
    let out = env
        .cmd()
        .args([
            "run",
            &format!("curl -H 'Authorization: token {token}' https://api.github.com/user"),
        ])
        .assert()
        .get_output()
        .clone();
    assert!(!String::from_utf8_lossy(&out.stderr).contains(&token));
    let log = std::fs::read_to_string(env.home.path().join("audit.jsonl")).unwrap();
    assert!(!log.contains(&token), "audit log leaked a secret");
    assert!(log.contains("[REDACTED]"));
}

#[test]
fn hostile_commands_cannot_repaint_the_terminal() {
    let env = Env::initialized();
    let out = env
        .cmd()
        .args(["run", "rm -rf ./x \x1b[2K\x1b[1G\u{202E}ls"])
        .assert()
        .code(126)
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains('\x1b'), "raw escape reached the terminal");
    assert!(!stderr.contains('\u{202E}'));
    assert!(stderr.contains("\\e[2K") && stderr.contains("<U+202E>"));
}

#[test]
fn interactive_shell_warning() {
    let env = Env::initialized();
    env.cmd()
        .args(["run", "bash"])
        .write_stdin("exit 0\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("NOT inspected"));
}

// ------------------------------------------------------------------ check

#[test]
fn check_exit_codes() {
    let env = Env::initialized();
    env.cmd()
        .args(["check", "git status"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("allowed"));
    env.cmd()
        .args(["check", "rm -rf ./test"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("BLOCKED"));
    env.cmd()
        .args(["check", "git push -f origin feature/login"])
        .assert()
        .code(3);
    env.cmd().args(["check", "--read", ".env"]).assert().code(1);
    env.cmd()
        .args(["check", "--fetch", "https://github.com/x"])
        .assert()
        .code(0);
    env.cmd()
        .args(["check", "--fetch", "https://unknown.example.net"])
        .assert()
        .code(3);
    env.cmd()
        .args(["check", "--write", ".sentinel/policy.yml"])
        .assert()
        .code(1);
    env.cmd()
        .arg("check")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("nothing to check"));
}

#[test]
fn check_json() {
    let env = Env::initialized();
    let out = env
        .cmd()
        .args(["check", "--json", "git push --force origin main"])
        .assert()
        .code(1)
        .get_output()
        .clone();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["decision"], "deny");
    assert_eq!(v["rule"], "block-protected-branch-rewrite");
    assert_eq!(v["risk"], "critical");
    assert_eq!(v["findings"][0]["id"], "git.protected-branch");
    assert_eq!(v["facts"]["git_subcommands"][0], "push");
    assert!(v["policy"].as_str().unwrap().ends_with("policy.yml"));
}

#[test]
fn explicit_policy_flag() {
    let env = Env::initialized();
    let strict = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policies/strict.yml");
    env.cmd().args(["check", "rm notes.txt"]).assert().code(0);
    env.cmd()
        .arg("--policy")
        .arg(&strict)
        .args(["check", "rm notes.txt"])
        .assert()
        .code(3);
}

// -------------------------------------------------------------------- log

#[test]
fn log_filters_and_json() {
    let env = Env::initialized();
    env.cmd().args(["run", "true"]).assert().success();
    env.cmd().args(["run", "rm -rf ./test"]).assert().code(126);
    env.cmd().args(["check", "ls"]).assert().success();
    let out = env
        .cmd()
        .args(["log", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let lines: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    for field in [
        "timestamp",
        "agent",
        "action",
        "risk",
        "decision",
        "outcome",
        "reason",
        "cwd",
        "duration_ms",
    ] {
        assert!(lines[1].get(field).is_some(), "missing {field}");
    }
    let out = env
        .cmd()
        .args(["log", "--denied", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 1);
    env.cmd()
        .args(["log", "--today"])
        .assert()
        .success()
        .stdout(predicate::str::contains("blocked"))
        .stdout(predicate::str::contains("rm -rf ./test"));
    env.cmd()
        .args(["log", "--agent", "nobody"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no matching events"));
}

// ------------------------------------------------------------------ hooks

#[test]
fn claude_code_hook_protocol() {
    let env = Env::initialized();
    std::fs::write(env.dir().join(".env"), "API_KEY=abcdef0123456789abcdef\n").unwrap();
    let cases = [
        ("claude-code/bash-rm.json", Some("deny")),
        ("claude-code/bash-force-push.json", Some("ask")),
        ("claude-code/bash-ls.json", None),
        ("claude-code/read-env.json", Some("deny")),
        ("claude-code/write-policy.json", Some("deny")),
        ("claude-code/webfetch-unknown.json", Some("ask")),
    ];
    for (fixture, expected) in cases {
        let out = env
            .cmd()
            .args(["hook", "claude-code"])
            .write_stdin(env.fixture(fixture))
            .assert()
            .code(0)
            .get_output()
            .clone();
        assert_eq!(hook_decision(&out.stdout).as_deref(), expected, "{fixture}");
    }
    let events = env.audit();
    assert!(events.iter().all(|e| e["agent"] == "claude-code"));
    assert_eq!(events[1]["outcome"], "asked");
    assert_eq!(events[0]["session"], "abc123");
}

#[test]
fn claude_code_hook_fails_to_ask_not_allow() {
    let env = Env::initialized();
    for input in ["", "{", "[]", r#"{"tool_name":"Bash","tool_input":{}}"#] {
        let out = env
            .cmd()
            .args(["hook", "claude-code"])
            .write_stdin(input)
            .assert()
            .code(0)
            .get_output()
            .clone();
        assert_eq!(
            hook_decision(&out.stdout).as_deref(),
            Some("ask"),
            "input {input:?}"
        );
    }
    // A broken policy must not turn the hook into an open door either.
    std::fs::write(
        env.dir().join(".sentinel/policy.yml"),
        "version: 1\nrules: [oops",
    )
    .unwrap();
    let out = env
        .cmd()
        .args(["hook", "claude-code"])
        .write_stdin(env.fixture("claude-code/bash-ls.json"))
        .assert()
        .code(0)
        .get_output()
        .clone();
    assert_eq!(hook_decision(&out.stdout).as_deref(), Some("ask"));
}

#[test]
fn claude_code_hook_uses_project_dir() {
    let env = Env::initialized();
    let sub = env.dir().join("packages/web");
    std::fs::create_dir_all(&sub).unwrap();
    let payload = env.fixture("claude-code/bash-rm.json").replace(
        &env.dir().to_string_lossy().to_string(),
        &sub.to_string_lossy(),
    );
    let out = env
        .cmd()
        .env("CLAUDE_PROJECT_DIR", env.dir())
        .args(["hook", "claude-code"])
        .write_stdin(payload)
        .assert()
        .code(0)
        .get_output()
        .clone();
    assert_eq!(hook_decision(&out.stdout).as_deref(), Some("deny"));
}

#[test]
fn codex_hook_denies_what_it_cannot_ask() {
    let env = Env::initialized();
    for fixture in [
        "codex/bash-force-push.json",
        "codex/apply-patch-policy.json",
    ] {
        let out = env
            .cmd()
            .args(["hook", "codex"])
            .write_stdin(env.fixture(fixture))
            .assert()
            .code(0)
            .get_output()
            .clone();
        assert_eq!(
            hook_decision(&out.stdout).as_deref(),
            Some("deny"),
            "{fixture}"
        );
    }
    let out = env
        .cmd()
        .args(["hook", "codex"])
        .write_stdin("garbage")
        .assert()
        .code(0)
        .get_output()
        .clone();
    assert_eq!(hook_decision(&out.stdout).as_deref(), Some("deny"));
}

#[test]
fn generic_hook_protocol() {
    let env = Env::initialized();
    let cwd = env.dir().to_string_lossy().to_string();
    let run = |input: String, code: i32| {
        let out = env
            .cmd()
            .args(["hook", "generic"])
            .write_stdin(input)
            .assert()
            .code(code)
            .get_output()
            .clone();
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };
    let v = run(
        serde_json::json!({"kind": "shell", "command": "ls", "cwd": cwd}).to_string(),
        0,
    );
    assert_eq!(v["decision"], "allow");
    let v = run(
        serde_json::json!({"kind": "shell", "command": "rm -rf /", "cwd": cwd, "agent": "my-bot"})
            .to_string(),
        1,
    );
    assert_eq!(v["decision"], "deny");
    let v = run(serde_json::json!([{"kind": "shell", "command": "ls", "cwd": cwd}, {"kind": "network", "url": "https://unknown.example.net", "cwd": cwd}]).to_string(), 3);
    assert_eq!(v["decision"], "confirm");
    run("nope".into(), 1);
    assert!(env.audit().iter().any(|e| e["agent"] == "my-bot"));
}

// ----------------------------------------------------------------- policy

#[test]
fn policy_commands() {
    let env = Env::initialized();
    env.cmd()
        .args(["policy", "test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("passed"));
    env.cmd()
        .args(["policy", "validate"])
        .assert()
        .success()
        .stdout(predicate::str::contains("is valid"));
    env.cmd()
        .args(["policy", "findings"])
        .assert()
        .success()
        .stdout(predicate::str::contains("git.force-push"));
    env.cmd()
        .args(["policy", "path"])
        .assert()
        .success()
        .stdout(predicate::str::contains(".sentinel/policy.yml"));
    env.cmd()
        .args(["policy", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("block-recursive-delete"));

    let bad = env.dir().join("bad.yml");
    std::fs::write(
        &bad,
        "version: 1\nrules:\n  - name: x\n    match: { comand_contains: rm }\n    action: deny\n",
    )
    .unwrap();
    env.cmd()
        .args(["policy", "validate"])
        .arg(&bad)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("comand_contains"));

    let failing = env.dir().join("failing.yml");
    std::fs::write(
        &failing,
        "version: 1\ntests:\n  - { command: 'rm -rf ./x', expect: deny }\n",
    )
    .unwrap();
    env.cmd()
        .arg("--policy")
        .arg(&failing)
        .args(["policy", "test"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("got allow"));
}

#[test]
fn broken_policy_is_an_error_not_a_bypass() {
    let env = Env::initialized();
    std::fs::write(
        env.dir().join(".sentinel/policy.yml"),
        "version: 1\ndefault: allow\nrules:\n  - name: x\n    match: {}\n    action: allow\n",
    )
    .unwrap();
    std::fs::create_dir(env.dir().join("test")).unwrap();
    env.cmd()
        .args(["run", "rm -rf ./test"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("invalid policy"));
    assert!(env.dir().join("test").is_dir());
}

#[test]
fn status_runs_without_policy() {
    let env = Env::new();
    env.cmd()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("built-in default"));
}

#[test]
fn closed_stdout_is_not_a_panic() {
    let env = Env::initialized();
    for _ in 0..30 {
        env.cmd().args(["run", "true"]).assert().success();
    }
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "{} log --all | head -1",
            assert_cmd::cargo::cargo_bin("sentinel").display()
        ))
        .env("SENTINEL_HOME", env.home.path())
        .current_dir(env.dir())
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}
