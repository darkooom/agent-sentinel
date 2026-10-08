//! Self-protection: an agent must not be able to edit the policy that
//! constrains it, forge session grants, or unregister the hook.
//!
//! This only covers modifications sentinel can see (shell commands and file
//! tool calls routed through it). It is not a substitute for file
//! permissions; see docs/security-model.md.

use std::path::Path;

use super::{Out, Scope};
use crate::command::{Executes, Invocation};
use crate::{Finding, Risk};

/// What a path protects, if anything.
pub(crate) fn protected(path: &Path, extra: &[std::path::PathBuf]) -> Option<&'static str> {
    if path.components().any(|c| c.as_os_str() == ".sentinel") {
        return Some("the agent-sentinel policy");
    }
    if extra.iter().any(|p| path.starts_with(p)) {
        return Some("agent-sentinel's configuration or state");
    }
    let text = path.to_string_lossy().replace('\\', "/");
    const HOOK_CONFIGS: &[(&str, &str)] = &[
        (
            "/.claude/settings.json",
            "Claude Code settings (hook registration)",
        ),
        (
            "/.claude/settings.local.json",
            "Claude Code settings (hook registration)",
        ),
        ("/.codex/hooks.json", "Codex hook configuration"),
        ("/.codex/config.toml", "Codex configuration"),
        ("/.cursor/hooks.json", "Cursor hook configuration"),
        ("/.gemini/settings.json", "Gemini CLI settings"),
    ];
    HOOK_CONFIGS
        .iter()
        .find(|(suffix, _)| text.ends_with(suffix))
        .map(|(_, what)| *what)
}

/// Programs that cannot modify the files they are given.
fn read_only(inv: &Invocation) -> bool {
    match inv.exe.as_str() {
        "cat" | "less" | "more" | "head" | "tail" | "bat" | "batcat" | "grep" | "egrep"
        | "fgrep" | "rg" | "ag" | "ls" | "stat" | "file" | "wc" | "diff" | "cmp" | "jq"
        | "test" | "[" | "[[" | "cd" | "echo" | "printf" | "tree" | "realpath" | "readlink"
        | "md5sum" | "shasum" | "sha256sum" | "view" | "nl" | "od" | "xxd" | "hexdump"
        | "strings" | "sort" | "uniq" | "cut" => true,
        "sed" | "perl" => !inv.has_flag(Some('i'), &["--in-place"]),
        "yq" => !inv.has_flag(Some('i'), &["--inplace"]),
        "git" => inv.positionals().first().is_some_and(|s| {
            matches!(
                s.text.as_str(),
                "status"
                    | "diff"
                    | "log"
                    | "show"
                    | "blame"
                    | "add"
                    | "ls-files"
                    | "check-ignore"
                    | "grep"
                    | "commit"
            )
        }),
        "sentinel" | "agent-sentinel" => {
            !inv.positionals().first().is_some_and(|s| s.text == "init")
        }
        _ => false,
    }
}

pub(crate) fn detect(scope: &Scope, out: &mut Out) {
    let extra = &scope.ctx.protected_paths;
    for inv in &scope.set.invocations {
        for (name, _) in &inv.assignments {
            if name.starts_with("SENTINEL_") {
                out.push(Finding::new(
                    "sentinel.tamper",
                    Risk::Critical,
                    format!("Overrides agent-sentinel configuration via {name}"),
                ));
            }
        }
        if matches!(
            inv.exe.as_str(),
            "export" | "unset" | "env" | "declare" | "typeset" | "setenv"
        ) {
            if let Some(w) = inv
                .args()
                .iter()
                .find(|w| w.text.trim_start_matches('-').starts_with("SENTINEL_"))
            {
                let name = w.text.split('=').next().unwrap_or(&w.text);
                out.push(Finding::new(
                    "sentinel.tamper",
                    Risk::Critical,
                    format!("Overrides agent-sentinel configuration via {name}"),
                ));
            }
        }
        if matches!(inv.exe.as_str(), "sentinel" | "agent-sentinel")
            && inv.positionals().first().is_some_and(|s| s.text == "init")
        {
            out.push(Finding::new(
                "sentinel.tamper",
                Risk::Critical,
                "Re-initializes the agent-sentinel policy",
            ));
        }

        let mut targets: Vec<std::path::PathBuf> = scope
            .redirect_writes(inv)
            .into_iter()
            .filter_map(|(_, p)| p)
            .collect();
        if !read_only(inv) {
            targets.extend(scope.operands(inv).into_iter().filter_map(|o| o.path));
            targets.extend(scope.write_targets(inv).into_iter().filter_map(|(_, p)| p));
        }
        for path in targets {
            if let Some(what) = protected(&path, extra) {
                out.push(Finding::new(
                    "sentinel.tamper",
                    Risk::Critical,
                    format!("Modifies {what}: {}", scope.show(&path)),
                ));
                break;
            }
        }

        if let Some(Executes::InlineCode { interpreter, code }) = &inv.executes {
            if code.contains(".sentinel/")
                || code.contains(".claude/settings")
                || code.contains("SENTINEL_")
            {
                out.push(Finding::new(
                    "sentinel.tamper",
                    Risk::Critical,
                    format!("Inline {interpreter} code references agent-sentinel's configuration"),
                ));
            }
        }
    }
}
