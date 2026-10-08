use std::path::{Path, PathBuf};

use globset::Glob;

use super::{Out, Scope};
use crate::command::Invocation;
use crate::shell::Word;
use crate::{Finding, Risk};

/// Configuration keys whose value is executed by git.
const EXEC_KEYS: &[&str] = &[
    "core.sshcommand",
    "core.pager",
    "core.editor",
    "core.fsmonitor",
    "core.hookspath",
    "core.gitproxy",
    "core.askpass",
    "sequence.editor",
    "diff.external",
    "gpg.program",
    "protocol.ext.allow",
    "uploadpack.packobjectshook",
    "credential.helper",
];

fn is_exec_key(key: &str, value: &str) -> bool {
    let key = key.to_ascii_lowercase();
    if key.starts_with("alias.") {
        return value.starts_with('!');
    }
    if key == "credential.helper" {
        return value.starts_with('!');
    }
    EXEC_KEYS.contains(&key.as_str())
        || key.starts_with("pager.")
        || (key.starts_with("filter.")
            && (key.ends_with(".clean") || key.ends_with(".smudge") || key.ends_with(".process")))
        || (key.starts_with("diff.") && key.ends_with(".textconv"))
        || (key.starts_with("merge.") && key.ends_with(".driver"))
}

struct Git<'a> {
    sub: String,
    args: &'a [Word],
    dir: Option<PathBuf>,
}

fn parse<'a>(scope: &Scope, inv: &'a Invocation, out: &mut Out) -> Option<Git<'a>> {
    let args = inv.args();
    let mut dir = inv.cwd.clone();
    let mut i = 0;
    while i < args.len() {
        let t = args[i].text.as_str();
        match t {
            "-C" => {
                if let Some(w) = args.get(i + 1) {
                    dir = dir.and_then(|d| crate::paths::resolve_word(w, Some(&d), scope.home()));
                }
                i += 2;
            }
            "-c" => {
                if let Some((key, value)) = args.get(i + 1).and_then(|w| w.text.split_once('=')) {
                    if is_exec_key(key, value) {
                        out.push(Finding::new(
                            "git.config-exec",
                            Risk::Critical,
                            format!("git -c {key}=… runs an arbitrary command"),
                        ));
                    }
                }
                i += 2;
            }
            "--git-dir" | "--work-tree" | "--namespace" | "--config-env" | "--super-prefix" => {
                i += 2
            }
            _ if t.starts_with('-') => i += 1,
            _ => {
                return Some(Git {
                    sub: t.to_string(),
                    args: &args[i + 1..],
                    dir,
                })
            }
        }
    }
    None
}

impl Git<'_> {
    fn has(&self, short: Option<char>, long: &[&str]) -> bool {
        self.args.iter().any(|w| {
            let t = w.text.as_str();
            long.iter()
                .any(|l| t == *l || t.starts_with(&format!("{l}=")))
                || short.is_some_and(|c| {
                    t.starts_with('-') && !t.starts_with("--") && t[1..].contains(c)
                })
        })
    }

    fn positionals(&self) -> Vec<&str> {
        let mut out = Vec::new();
        let mut done = false;
        for w in self.args {
            let t = w.text.as_str();
            if !done && t == "--" {
                done = true;
                continue;
            }
            if !done && t.starts_with('-') && t.len() > 1 {
                continue;
            }
            out.push(t);
        }
        out
    }

    fn after_double_dash(&self) -> bool {
        self.args.iter().any(|w| w.text == "--")
    }
}

pub(crate) fn detect(scope: &Scope, out: &mut Out) {
    for inv in &scope.set.invocations {
        if inv.exe != "git" {
            continue;
        }
        let Some(git) = parse(scope, inv, out) else {
            continue;
        };
        out.facts.git_subcommands.push(git.sub.clone());
        let current = || {
            if scope.ctx.inspect_files {
                git.dir.as_deref().and_then(current_branch)
            } else {
                None
            }
        };
        match git.sub.as_str() {
            "push" => push(scope, &git, current(), out),
            "reset" if git.has(None, &["--hard"]) => {
                out.push(Finding::new(
                    "git.reset-hard",
                    Risk::High,
                    "git reset --hard discards uncommitted changes",
                ));
            }
            "clean" => {
                let forced = git.has(Some('f'), &["--force"]);
                let dry =
                    git.has(Some('n'), &["--dry-run"]) || git.has(Some('i'), &["--interactive"]);
                if forced && !dry {
                    let mut what = String::from("git clean deletes untracked files");
                    if git.has(Some('d'), &[]) {
                        what.push_str(" and directories");
                    }
                    if git.has(Some('x'), &[]) || git.has(Some('X'), &[]) {
                        what.push_str(", including ignored files such as .env");
                    }
                    out.push(Finding::new("git.clean", Risk::High, what));
                }
            }
            "checkout" => {
                if git.has(Some('p'), &["--patch"]) {
                    continue;
                }
                let pos = git.positionals();
                if git.has(Some('f'), &["--force"]) {
                    out.push(Finding::new(
                        "git.discard-changes",
                        Risk::High,
                        "git checkout --force discards local changes",
                    ));
                } else if pos.iter().any(|p| matches!(*p, "." | ":/" | "*" | "./")) {
                    out.push(Finding::new(
                        "git.discard-changes",
                        Risk::High,
                        "git checkout . discards all uncommitted changes",
                    ));
                } else if git.after_double_dash() && !pos.is_empty() {
                    out.push(Finding::new(
                        "git.discard-changes",
                        Risk::Medium,
                        format!("git checkout discards changes to {}", pos.join(", ")),
                    ));
                }
            }
            "restore" => {
                let staged_only =
                    git.has(Some('S'), &["--staged"]) && !git.has(Some('W'), &["--worktree"]);
                let pos = git.positionals();
                if staged_only || pos.is_empty() || git.has(Some('p'), &["--patch"]) {
                    continue;
                }
                if pos.iter().any(|p| matches!(*p, "." | ":/" | "*" | "./")) {
                    out.push(Finding::new(
                        "git.discard-changes",
                        Risk::High,
                        "git restore . discards all uncommitted changes",
                    ));
                } else {
                    out.push(Finding::new(
                        "git.discard-changes",
                        Risk::Medium,
                        format!("git restore discards changes to {}", pos.join(", ")),
                    ));
                }
            }
            "switch" if git.has(Some('f'), &["--force", "--discard-changes"]) => {
                out.push(Finding::new(
                    "git.discard-changes",
                    Risk::High,
                    "git switch --discard-changes drops local changes",
                ));
            }
            "stash" => match git.positionals().first().copied() {
                Some("drop") => out.push(Finding::new(
                    "git.discard-changes",
                    Risk::Medium,
                    "git stash drop deletes a stash entry",
                )),
                Some("clear") => out.push(Finding::new(
                    "git.discard-changes",
                    Risk::High,
                    "git stash clear deletes every stash entry",
                )),
                _ => {}
            },
            "branch" => branch(scope, &git, out),
            "rebase" => {
                if git.has(
                    None,
                    &[
                        "--abort",
                        "--continue",
                        "--skip",
                        "--quit",
                        "--edit-todo",
                        "--show-current-patch",
                    ],
                ) {
                    continue;
                }
                match current().filter(|b| is_protected(scope, Some(b))) {
                    Some(b) => out.push(Finding::new(
                        "git.history-rewrite",
                        Risk::High,
                        format!("Rebase rewrites the history of protected branch '{b}'"),
                    )),
                    None => out.push(Finding::new(
                        "git.history-rewrite",
                        Risk::Medium,
                        "Rebase rewrites commit history",
                    )),
                }
            }
            "commit" if git.has(None, &["--amend"]) => {
                out.push(Finding::new(
                    "git.history-rewrite",
                    Risk::Medium,
                    "git commit --amend rewrites the last commit",
                ));
            }
            "filter-branch" | "filter-repo" => {
                out.push(Finding::new(
                    "git.history-rewrite",
                    Risk::High,
                    format!("git {} rewrites the entire history", git.sub),
                ));
            }
            "reflog"
                if matches!(
                    git.positionals().first().copied(),
                    Some("expire" | "delete")
                ) =>
            {
                out.push(Finding::new(
                    "git.history-rewrite",
                    Risk::High,
                    "Expiring reflog entries removes recovery points",
                ));
            }
            "gc" if git
                .args
                .iter()
                .any(|w| w.text == "--prune=now" || w.text == "--prune=all") =>
            {
                out.push(Finding::new(
                    "git.history-rewrite",
                    Risk::High,
                    "git gc --prune=now permanently deletes unreachable commits",
                ));
            }
            "update-ref" if git.has(Some('d'), &[]) => {
                out.push(Finding::new(
                    "git.branch-delete",
                    Risk::High,
                    "git update-ref -d deletes a ref",
                ));
            }
            "config" => {
                let pos = git.positionals();
                if let [key, value, ..] = pos.as_slice() {
                    if is_exec_key(key, value) {
                        out.push(Finding::new(
                            "git.config-exec",
                            Risk::High,
                            format!("Sets {key}, which makes git run a command"),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
}

fn push(scope: &Scope, git: &Git, current: Option<String>, out: &mut Out) {
    if git.has(Some('n'), &["--dry-run"]) {
        return;
    }
    let lease = git.has(None, &["--force-with-lease"]);
    let force = lease || git.has(Some('f'), &["--force"]);
    let mirror = git.has(None, &["--mirror"]);
    let all = mirror || git.has(None, &["--all", "--branches"]);
    let delete = git.has(Some('d'), &["--delete"]);

    // Skip values of options that take an argument.
    let mut pos: Vec<&str> = Vec::new();
    let mut skip = false;
    for w in git.args {
        let t = w.text.as_str();
        if skip {
            skip = false;
            continue;
        }
        if matches!(
            t,
            "--repo" | "-o" | "--push-option" | "--receive-pack" | "--exec"
        ) {
            skip = true;
            continue;
        }
        if t.starts_with('-') && t.len() > 1 {
            continue;
        }
        pos.push(t);
    }
    let remote = pos.first().copied().unwrap_or("origin");
    let mut targets: Vec<(Option<String>, bool, bool)> = Vec::new(); // (branch, force, delete)
    if all {
        targets.push((None, force || mirror, false));
    }
    for spec in pos.iter().skip(1) {
        let (plus, spec) = match spec.strip_prefix('+') {
            Some(rest) => (true, rest),
            None => (false, *spec),
        };
        let dst = match spec.split_once(':') {
            Some((s, d)) => {
                if d.is_empty() {
                    s
                } else {
                    d
                }
            }
            None => spec,
        };
        let ref_delete = spec.starts_with(':') && !dst.is_empty();
        let name = if dst == "HEAD" {
            current.clone()
        } else {
            Some(dst.trim_start_matches("refs/heads/").to_string())
        };
        targets.push((name, force || plus, delete || ref_delete));
    }
    if targets.is_empty() {
        // `git push` / `git push origin`: pushes the current branch.
        targets.push((current, force, delete));
    }
    if git.has(None, &["--prune"]) {
        out.push(Finding::new(
            "git.branch-delete",
            Risk::High,
            format!("git push --prune deletes remote branches on {remote}"),
        ));
    }
    for (branch, forced, deleted) in targets {
        let protected = is_protected(scope, branch.as_deref());
        let label = branch
            .clone()
            .unwrap_or_else(|| "the current branch (unresolved)".into());
        if deleted {
            if protected {
                out.push(Finding::new(
                    "git.protected-branch",
                    Risk::Critical,
                    format!("Deletes protected branch '{label}' on {remote}"),
                ));
            } else {
                out.push(Finding::new(
                    "git.branch-delete",
                    Risk::High,
                    format!("Deletes branch '{label}' on {remote}"),
                ));
            }
        } else if forced {
            let how = if lease {
                "Force push (with lease)"
            } else if mirror {
                "Mirror push"
            } else {
                "Force push"
            };
            if protected {
                let target = if all {
                    "all branches, including protected ones".to_string()
                } else {
                    format!("protected branch '{label}'")
                };
                out.push(Finding::new(
                    "git.protected-branch",
                    Risk::Critical,
                    format!("{how} to {target}"),
                ));
            } else {
                out.push(Finding::new(
                    "git.force-push",
                    Risk::High,
                    format!("{how} to {remote}/{label}"),
                ));
            }
        } else if protected && branch.is_some() {
            out.push(Finding::new(
                "git.push-protected",
                Risk::Medium,
                format!("Pushes directly to protected branch '{label}'"),
            ));
        }
    }
}

fn branch(scope: &Scope, git: &Git, out: &mut Out) {
    let force_delete = git.args.iter().any(|w| {
        let t = w.text.as_str();
        t.starts_with('-') && !t.starts_with("--") && t.contains('D')
    }) || (git.has(Some('d'), &["--delete"])
        && git.has(Some('f'), &["--force"]));
    let delete = force_delete || git.has(Some('d'), &["--delete"]);
    if !delete {
        return;
    }
    for name in git.positionals() {
        if is_protected(scope, Some(name)) {
            out.push(Finding::new(
                "git.protected-branch",
                Risk::Critical,
                format!("Deletes protected branch '{name}'"),
            ));
        } else if force_delete {
            out.push(Finding::new(
                "git.branch-delete",
                Risk::High,
                format!("Force-deletes branch '{name}' (unmerged commits are lost)"),
            ));
        } else {
            out.push(Finding::new(
                "git.branch-delete",
                Risk::Medium,
                format!("Deletes branch '{name}'"),
            ));
        }
    }
}

/// Unknown targets count as protected: fail closed.
fn is_protected(scope: &Scope, branch: Option<&str>) -> bool {
    let Some(branch) = branch else { return true };
    scope.ctx.protected_branches.iter().any(|pattern| {
        Glob::new(pattern)
            .map(|g| g.compile_matcher().is_match(branch))
            .unwrap_or(pattern == branch)
    })
}

/// Read the checked-out branch from `.git/HEAD` without running git.
pub(crate) fn current_branch(start: &Path) -> Option<String> {
    let mut dir = Some(start);
    for _ in 0..64 {
        let d = dir?;
        let dot_git = d.join(".git");
        if dot_git.is_dir() {
            return read_head(&dot_git.join("HEAD"));
        }
        if dot_git.is_file() {
            // Worktrees and submodules: `.git` is a file with `gitdir: <path>`.
            let content = std::fs::read_to_string(&dot_git).ok()?;
            let gitdir = content.strip_prefix("gitdir:")?.trim();
            let gitdir = if Path::new(gitdir).is_absolute() {
                PathBuf::from(gitdir)
            } else {
                d.join(gitdir)
            };
            return read_head(&gitdir.join("HEAD"));
        }
        dir = d.parent();
    }
    None
}

fn read_head(path: &Path) -> Option<String> {
    let head = std::fs::read_to_string(path).ok()?;
    head.trim()
        .strip_prefix("ref: refs/heads/")
        .map(str::to_string)
}
