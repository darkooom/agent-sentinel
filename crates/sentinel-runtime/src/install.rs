//! Registering the Claude Code hook.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

pub const HOOK_MARKER: &str = "hook claude-code";

#[derive(Debug, PartialEq, Eq)]
pub enum InstallResult {
    Installed(PathBuf),
    AlreadyInstalled(PathBuf),
}

/// Add a `PreToolUse` hook running `<sentinel> hook claude-code` for every
/// tool to `<project>/.claude/settings.local.json`. The local settings file
/// is used because the command contains an absolute, machine-specific path.
/// Existing settings are preserved.
pub fn install_claude_hook(project: &Path, sentinel: &Path) -> Result<InstallResult> {
    let path = project.join(".claude").join("settings.local.json");
    let mut root: Value = match std::fs::read_to_string(&path) {
        Ok(text) if !text.trim().is_empty() => serde_json::from_str(&text)
            .with_context(|| format!("{} is not valid JSON", path.display()))?,
        Ok(_) => json!({}),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let Some(obj) = root.as_object_mut() else {
        bail!("{} must contain a JSON object", path.display());
    };
    if is_registered(obj) {
        return Ok(InstallResult::AlreadyInstalled(path));
    }
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    let Some(hooks) = hooks.as_object_mut() else {
        bail!("`hooks` in {} is not an object", path.display());
    };
    let pre = hooks.entry("PreToolUse").or_insert_with(|| json!([]));
    let Some(pre) = pre.as_array_mut() else {
        bail!("`hooks.PreToolUse` in {} is not an array", path.display());
    };
    pre.push(json!({
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": format!("{} {HOOK_MARKER}", shell_quote(&sentinel.to_string_lossy())),
            "timeout": 30
        }]
    }));
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
    std::fs::rename(&tmp, &path)?;
    Ok(InstallResult::Installed(path))
}

fn is_registered(obj: &Map<String, Value>) -> bool {
    obj.get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(Value::as_array)
        .is_some_and(|groups| {
            groups.iter().any(|g| {
                g.get("hooks").and_then(Value::as_array).is_some_and(|hs| {
                    hs.iter().any(|h| {
                        h.get("command")
                            .and_then(Value::as_str)
                            .is_some_and(|c| c.contains(HOOK_MARKER))
                    })
                })
            })
        })
}

/// Which settings files under `project` (and the user's home) register the
/// hook. Used by `sentinel status`.
pub fn claude_hook_locations(project: Option<&Path>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(p) = project {
        candidates.push(p.join(".claude/settings.json"));
        candidates.push(p.join(".claude/settings.local.json"));
    }
    if let Some(home) = std::env::home_dir() {
        candidates.push(home.join(".claude/settings.json"));
    }
    candidates
        .into_iter()
        .filter(|p| {
            std::fs::read_to_string(p)
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                .and_then(|v| v.as_object().map(is_registered))
                .unwrap_or(false)
        })
        .collect()
}

fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+:".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_into_existing_settings() {
        let dir = tempfile::tempdir().unwrap();
        let settings = dir.path().join(".claude/settings.local.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(
            &settings,
            r#"{"permissions":{"allow":["Bash(npm test)"]},"hooks":{"PostToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"fmt"}]}]}}"#,
        )
        .unwrap();
        let result = install_claude_hook(dir.path(), Path::new("/opt/bin/sentinel")).unwrap();
        assert_eq!(result, InstallResult::Installed(settings.clone()));
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["permissions"]["allow"][0], "Bash(npm test)");
        assert_eq!(v["hooks"]["PostToolUse"][0]["hooks"][0]["command"], "fmt");
        assert_eq!(v["hooks"]["PreToolUse"][0]["matcher"], "*");
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "/opt/bin/sentinel hook claude-code"
        );
        let again = install_claude_hook(dir.path(), Path::new("/opt/bin/sentinel")).unwrap();
        assert_eq!(again, InstallResult::AlreadyInstalled(settings));
        assert_eq!(claude_hook_locations(Some(dir.path())).len(), 1);
    }

    #[test]
    fn quotes_paths_with_spaces() {
        let dir = tempfile::tempdir().unwrap();
        install_claude_hook(dir.path(), Path::new("/Users/a b/sentinel")).unwrap();
        let text = std::fs::read_to_string(dir.path().join(".claude/settings.local.json")).unwrap();
        assert!(text.contains("'/Users/a b/sentinel' hook claude-code"));
    }

    #[test]
    fn refuses_to_clobber_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(dir.path().join(".claude/settings.local.json"), "{ not json").unwrap();
        assert!(install_claude_hook(dir.path(), Path::new("/s")).is_err());
    }
}
