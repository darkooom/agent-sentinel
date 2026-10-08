use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sentinel_policy::{Policy, PolicySource};

use crate::Paths;

pub const POLICY_DIR: &str = ".sentinel";
pub const POLICY_FILE: &str = "policy.yml";

pub struct LoadedPolicy {
    pub policy: Policy,
    /// Directory holding `.sentinel/`, else the enclosing git repository.
    pub project_root: Option<PathBuf>,
}

/// Find the policy that applies to `start`:
///
/// 1. `explicit` (the `--policy` flag or `SENTINEL_POLICY`)
/// 2. the nearest `.sentinel/policy.yml` in `start` or a parent
/// 3. the user policy in the config directory
/// 4. the built-in default
pub fn load_policy(explicit: Option<&Path>, start: &Path, paths: &Paths) -> Result<LoadedPolicy> {
    let git_root = find_up(start, |d| d.join(".git").exists());
    if let Some(path) = explicit {
        let policy = load_file(path)?;
        let project_root =
            find_up(start, |d| d.join(POLICY_DIR).join(POLICY_FILE).is_file()).or(git_root);
        return Ok(LoadedPolicy {
            policy,
            project_root,
        });
    }
    if let Some(dir) = find_up(start, |d| policy_in(d).is_some()) {
        let path = policy_in(&dir).expect("found above");
        return Ok(LoadedPolicy {
            policy: load_file(&path)?,
            project_root: Some(dir),
        });
    }
    let global = paths.global_policy();
    let policy = if global.is_file() {
        load_file(&global)?
    } else {
        Policy::builtin()
    };
    Ok(LoadedPolicy {
        policy,
        project_root: git_root,
    })
}

fn policy_in(dir: &Path) -> Option<PathBuf> {
    ["policy.yml", "policy.yaml"]
        .iter()
        .map(|f| dir.join(POLICY_DIR).join(f))
        .find(|p| p.is_file())
}

pub fn load_file(path: &Path) -> Result<Policy> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read policy {}", path.display()))?;
    Policy::from_yaml(&text, PolicySource::File(path.to_path_buf()))
        .with_context(|| format!("invalid policy {}", path.display()))
}

pub fn find_up(start: &Path, pred: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        if pred(d) {
            return Some(d.to_path_buf());
        }
        dir = d.parent();
    }
    None
}
