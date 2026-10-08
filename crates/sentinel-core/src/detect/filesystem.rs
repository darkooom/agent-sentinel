use std::path::{Path, PathBuf};

use super::{Out, Scope};
use crate::command::{Executes, Invocation};
use crate::shell::Word;
use crate::{paths, Finding, Risk};

/// Directories that are safe to delete because a build regenerates them.
const ARTIFACT_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".cache",
    ".parcel-cache",
    "coverage",
    ".nyc_output",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".gradle",
    ".venv",
    "venv",
    "obj",
    ".eggs",
    ".angular",
    ".expo",
    "DerivedData",
    ".dart_tool",
    "_build",
    "deps",
    ".terraform",
];

const SYSTEM_DIRS: &[&str] = &[
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib32",
    "/lib64",
    "/opt",
    "/proc",
    "/root",
    "/sbin",
    "/srv",
    "/sys",
    "/usr",
    "/var",
    "/System",
    "/Library",
    "/Applications",
    "/Users",
    "/private",
    "/Volumes",
    "/mnt",
    "/media",
    "/snap",
    "/nix",
    "/cores",
];

const PERSONAL_DIRS: &[&str] = &[
    "Documents",
    "Desktop",
    "Downloads",
    "Pictures",
    "Music",
    "Movies",
    "Videos",
    "Library",
    "Projects",
    "projects",
    "src",
    "code",
    "Code",
    "dev",
    "work",
    "Work",
    "workspace",
    "go",
    ".ssh",
    ".config",
    ".local",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
];

enum Target {
    Critical(String),
    Artifact,
    Normal,
    Unknown(String),
}

pub(crate) fn detect(scope: &Scope, out: &mut Out) {
    for inv in &scope.set.invocations {
        match inv.exe.as_str() {
            "rm" => rm(scope, inv, out),
            "rmdir" => {
                let targets = names(&inv.positionals());
                if !targets.is_empty() {
                    out.push(Finding::new(
                        "fs.delete",
                        Risk::Low,
                        format!("Removes empty directory {targets}"),
                    ));
                }
            }
            "unlink" => {
                let targets = names(&inv.positionals());
                out.push(Finding::new(
                    "fs.delete",
                    Risk::Medium,
                    format!("Deletes {targets}"),
                ));
            }
            "shred" | "srm" | "wipe" => {
                let targets = names(&inv.positionals());
                out.push(Finding::new(
                    "fs.delete",
                    Risk::High,
                    format!("Irrecoverably overwrites {targets}"),
                ));
            }
            "find" => find(scope, inv, out),
            "rsync" => {
                if inv.args().iter().any(|w| {
                    w.text.starts_with("--delete")
                        || w.text == "--del"
                        || w.text == "--remove-source-files"
                }) {
                    out.push(Finding::new(
                        "fs.recursive-delete",
                        Risk::High,
                        "rsync --delete removes files that are missing from the source",
                    ));
                }
            }
            "mv" => mv(scope, inv, out),
            "chmod" | "chown" | "chgrp" | "setfacl" => permissions(scope, inv, out),
            "dd" => {
                if let Some(of) = inv.args().iter().find_map(|w| w.text.strip_prefix("of=")) {
                    if is_block_device(of) {
                        out.push(Finding::new(
                            "fs.disk",
                            Risk::Critical,
                            format!("Writes raw data to disk device {of}"),
                        ));
                    }
                }
            }
            "wipefs" | "fdisk" | "sfdisk" | "cfdisk" | "parted" | "gdisk" | "sgdisk" | "mkswap"
            | "mke2fs" => {
                out.push(Finding::new(
                    "fs.disk",
                    Risk::Critical,
                    format!("{} modifies disk partitions or filesystems", inv.exe),
                ));
            }
            exe if exe.starts_with("mkfs") => {
                out.push(Finding::new(
                    "fs.disk",
                    Risk::Critical,
                    format!("{exe} formats a filesystem"),
                ));
            }
            "diskutil" => {
                let verb = inv
                    .positionals()
                    .first()
                    .map(|w| w.text.to_ascii_lowercase())
                    .unwrap_or_default();
                if verb.starts_with("erase")
                    || verb.starts_with("partition")
                    || matches!(
                        verb.as_str(),
                        "zerodisk" | "randomdisk" | "secureerase" | "reformat" | "apfs"
                    )
                {
                    out.push(Finding::new(
                        "fs.disk",
                        Risk::Critical,
                        format!("diskutil {verb} erases or repartitions a disk"),
                    ));
                }
            }
            _ => {}
        }
        if let Some(Executes::InlineCode { interpreter, code }) = &inv.executes {
            if inline_recursive_delete(code) {
                out.push(Finding::new(
                    "fs.recursive-delete",
                    Risk::High,
                    format!("Inline {interpreter} code deletes directory trees"),
                ));
            }
        }
        windows_delete(scope, inv, out);
        writes(scope, inv, out);
    }
}

fn inline_recursive_delete(code: &str) -> bool {
    static API: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)\brmtree\s*\(|\brmSync\s*\([^)]*recursive|\bfs\.rm\s*\([^)]*recursive|\brimraf\b|\brm_rf\b|\bFileUtils\.rm_r|\bremove_dir_all\b|\bos\.RemoveAll\b|\bdeleteRecursively\b|Remove-Item\b[^;
]*-Recurse",
        )
        .expect("valid regex")
    });
    API.is_match(code)
}

/// PowerShell `Remove-Item -Recurse` and cmd.exe `rd /s` (Claude Code's
/// PowerShell tool). Parsed with POSIX rules, so this is best effort.
fn windows_delete(scope: &Scope, inv: &Invocation, out: &mut Out) {
    let args = inv.args();
    let recursive = match inv.exe.as_str() {
        "remove-item" | "ri" | "del" | "erase" => args.iter().any(|w| {
            let t = w.text.to_ascii_lowercase();
            t.len() > 1 && "-recurse".starts_with(t.as_str()) && t.starts_with("-r")
        }),
        "rd" => args.iter().any(|w| w.text.eq_ignore_ascii_case("/s")),
        _ => false,
    };
    if !recursive {
        return;
    }
    let targets: Vec<&Word> = args
        .iter()
        .filter(|w| !w.text.starts_with(['-', '/']) || w.text.starts_with("./"))
        .collect();
    for word in &targets {
        if let Target::Critical(reason) = classify_target(scope, inv, word) {
            out.push(Finding::new(
                "fs.delete-critical",
                Risk::Critical,
                format!("Recursive delete: {reason}"),
            ));
            return;
        }
    }
    out.push(Finding::new(
        "fs.recursive-delete",
        Risk::High,
        format!("Recursive delete of {}", names(&targets)),
    ));
}

fn names(words: &[&Word]) -> String {
    let list: Vec<&str> = words.iter().take(4).map(|w| w.text.as_str()).collect();
    let mut s = list.join(", ");
    if words.len() > 4 {
        s.push_str(&format!(" (+{} more)", words.len() - 4));
    }
    if s.is_empty() {
        s = "files".into();
    }
    s
}

fn rm(scope: &Scope, inv: &Invocation, out: &mut Out) {
    let recursive = inv.has_flag(Some('r'), &["--recursive"]) || inv.has_flag(Some('R'), &[]);
    let targets = inv.positionals();
    if targets.is_empty() && !inv.dynamic_args {
        return;
    }
    if !recursive {
        let what = if targets.is_empty() {
            "files passed at runtime".to_string()
        } else {
            names(&targets)
        };
        out.push(Finding::new(
            "fs.delete",
            Risk::Medium,
            format!("Deletes {what}"),
        ));
        return;
    }

    let mut critical = Vec::new();
    let mut unknown = Vec::new();
    let mut normal = Vec::new();
    let mut artifacts = Vec::new();
    if inv.has_flag(None, &["--no-preserve-root"]) {
        critical.push("--no-preserve-root disables the / safeguard".to_string());
    }
    if inv.dynamic_args {
        unknown.push("targets are supplied at runtime".to_string());
    }
    for word in &targets {
        match classify_target(scope, inv, word) {
            Target::Critical(reason) => critical.push(reason),
            Target::Unknown(reason) => unknown.push(reason),
            Target::Artifact => artifacts.push(word.text.clone()),
            Target::Normal => normal.push(word.text.clone()),
        }
    }
    if !critical.is_empty() {
        out.push(
            Finding::new(
                "fs.delete-critical",
                Risk::Critical,
                format!("Recursive delete: {}", critical[0]),
            )
            .with_details(critical.iter().skip(1).cloned().collect()),
        );
    } else if !normal.is_empty() || !unknown.is_empty() {
        let mut what: Vec<String> = normal;
        what.extend(unknown);
        out.push(
            Finding::new(
                "fs.recursive-delete",
                Risk::High,
                format!("Recursive delete of {}", what[0]),
            )
            .with_details(what.iter().skip(1).cloned().collect()),
        );
    } else if !artifacts.is_empty() {
        out.push(Finding::new(
            "fs.delete-artifacts",
            Risk::Low,
            format!("Removes build artifacts: {}", artifacts.join(", ")),
        ));
    }
}

fn classify_target(scope: &Scope, inv: &Invocation, word: &Word) -> Target {
    if !word.is_static() {
        // `rm -rf "$DIR/"*` deletes from / when DIR is empty or unset.
        let text = &word.text;
        if let Some(var) = leading_unknown_var(word) {
            if text.len() > var.len() && text[var.len()..].starts_with('/') {
                return Target::Critical(format!("`{text}` expands to /… if {var} is empty"));
            }
        }
        return match paths::resolve_word(word, inv.cwd.as_deref(), scope.home()) {
            Some(path) => classify_path(scope, inv, word, &path),
            None => Target::Unknown(format!("`{text}` (only known at runtime)")),
        };
    }
    match scope.resolve(inv, word) {
        Some(path) => classify_path(scope, inv, word, &path),
        None => Target::Unknown(format!("`{}` (location unknown)", word.text)),
    }
}

fn leading_unknown_var(word: &Word) -> Option<String> {
    let text = &word.text;
    let var = word.vars.first()?;
    if matches!(var.as_str(), "HOME" | "PWD") {
        return None;
    }
    [format!("${{{var}}}"), format!("${var}")]
        .into_iter()
        .find(|p| text.starts_with(p.as_str()))
}

fn classify_path(scope: &Scope, inv: &Invocation, word: &Word, path: &Path) -> Target {
    // A glob deletes the contents of the directory it sits in.
    let (dir, contents) = if word.glob {
        (glob_base(path), true)
    } else {
        (path.to_path_buf(), false)
    };
    let prefix = if contents { "everything in " } else { "" };
    let shown = scope.show(&dir);

    if dir == Path::new("/") {
        return Target::Critical(format!("{prefix}/ (the root filesystem)"));
    }
    if let Some(home) = scope.home() {
        if dir == home {
            return Target::Critical(format!("{prefix}your home directory"));
        }
        if home.starts_with(&dir) {
            return Target::Critical(format!(
                "{prefix}{shown}, which contains your home directory"
            ));
        }
        if dir.parent() == Some(home) {
            let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if PERSONAL_DIRS.contains(&name) {
                return Target::Critical(format!("{prefix}~/{name}"));
            }
        }
    }
    if SYSTEM_DIRS.iter().any(|d| dir == Path::new(d)) || dir.parent() == Some(Path::new("/")) {
        return Target::Critical(format!("{prefix}system directory {}", dir.display()));
    }
    if let Some(cwd) = inv.cwd.as_deref() {
        if cwd.starts_with(&dir) {
            let what = if dir == cwd {
                "the current directory"
            } else {
                "a parent of the current directory"
            };
            return Target::Critical(format!("{prefix}{what} ({shown})"));
        }
    }
    if let Some(root) = scope.ctx.project_root.as_deref() {
        if root.starts_with(&dir) {
            return Target::Critical(format!("{prefix}the project root ({shown})"));
        }
        if dir == root.join(".git") {
            return Target::Critical("the project's .git directory (all history)".into());
        }
    }
    if dir.file_name().is_some_and(|n| n == ".git") {
        return Target::Critical(format!("{shown} (a git repository's history)"));
    }
    if !contents && is_artifact(scope, inv, word, path) {
        return Target::Artifact;
    }
    Target::Normal
}

fn glob_base(path: &Path) -> PathBuf {
    let mut base = PathBuf::new();
    for component in path.components() {
        let s = component.as_os_str().to_string_lossy();
        if s.contains(['*', '?', '[']) {
            break;
        }
        base.push(component.as_os_str());
    }
    base
}

fn is_artifact(scope: &Scope, inv: &Invocation, word: &Word, path: &Path) -> bool {
    let text = word.text.trim_end_matches('/');
    if word.tilde || Path::new(text).is_absolute() || text.split('/').any(|c| c == "..") {
        return false;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let named = ARTIFACT_DIRS.contains(&name) || name.ends_with(".egg-info");
    let inside = inv
        .cwd
        .as_deref()
        .is_some_and(|cwd| path.starts_with(cwd) && path != cwd);
    // A symlink named node_modules could point anywhere.
    let symlink = scope.ctx.inspect_files
        && std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
    named && inside && !symlink
}

fn find(scope: &Scope, inv: &Invocation, out: &mut Out) {
    if !inv.args().iter().any(|w| w.text == "-delete") {
        return;
    }
    let roots: Vec<&Word> = inv
        .args()
        .iter()
        .take_while(|w| !w.text.starts_with('-') && w.text != "(" && w.text != "!")
        .collect();
    let dot = Word::literal(".");
    let roots = if roots.is_empty() { vec![&dot] } else { roots };
    for root in roots {
        if let Target::Critical(reason) = classify_target(scope, inv, root) {
            out.push(Finding::new(
                "fs.delete-critical",
                Risk::Critical,
                format!("find -delete under {reason}"),
            ));
            return;
        }
    }
    out.push(Finding::new(
        "fs.recursive-delete",
        Risk::High,
        "find -delete removes every matching file",
    ));
}

fn mv(scope: &Scope, inv: &Invocation, out: &mut Out) {
    let pos = inv.positionals();
    if pos.len() < 2 {
        return;
    }
    let dest = pos[pos.len() - 1];
    if dest.text == "/dev/null" {
        out.push(Finding::new(
            "fs.delete",
            Risk::Medium,
            format!("Moves {} to /dev/null", names(&pos[..pos.len() - 1])),
        ));
        return;
    }
    for src in &pos[..pos.len() - 1] {
        if let Target::Critical(reason) = classify_target(scope, inv, src) {
            if !src.glob {
                out.push(Finding::new(
                    "fs.delete-critical",
                    Risk::Critical,
                    format!("Moves away {reason}"),
                ));
            }
        }
    }
}

fn permissions(scope: &Scope, inv: &Invocation, out: &mut Out) {
    let recursive = inv.has_flag(Some('R'), &["--recursive"]);
    let pos = inv.positionals();
    if inv.exe == "chmod" {
        if let Some(mode) = pos.first().map(|w| w.text.as_str()) {
            let octal = mode.len() >= 3 && mode.chars().all(|c| c.is_digit(8));
            let others = mode.chars().last().and_then(|c| c.to_digit(8)).unwrap_or(0);
            let world_writable =
                (octal && others & 2 != 0) || mode.contains("o+w") || mode.contains("a+w");
            let special = mode.chars().next().and_then(|c| c.to_digit(8)).unwrap_or(0);
            let setid = mode.contains("+s") || (octal && mode.len() == 4 && special & 6 != 0);
            if world_writable {
                out.push(Finding::new(
                    "fs.permissions",
                    Risk::High,
                    format!("chmod {mode} makes files world-writable"),
                ));
            }
            if setid {
                out.push(Finding::new(
                    "fs.permissions",
                    Risk::High,
                    format!("chmod {mode} sets setuid/setgid"),
                ));
            }
        }
    }
    if !recursive {
        return;
    }
    let skip = if inv.exe == "setfacl" { 0 } else { 1 };
    for word in pos.iter().skip(skip) {
        if let Target::Critical(reason) = classify_target(scope, inv, word) {
            out.push(Finding::new(
                "fs.permissions",
                Risk::Critical,
                format!("{} -R on {reason}", inv.exe),
            ));
            return;
        }
    }
    out.push(Finding::new(
        "fs.permissions",
        Risk::High,
        format!(
            "Recursive {} changes permissions or ownership of a whole tree",
            inv.exe
        ),
    ));
}

fn is_block_device(path: &str) -> bool {
    [
        "/dev/sd",
        "/dev/hd",
        "/dev/vd",
        "/dev/xvd",
        "/dev/nvme",
        "/dev/disk",
        "/dev/rdisk",
        "/dev/mmcblk",
        "/dev/md",
        "/dev/dm-",
        "/dev/mapper/",
    ]
    .iter()
    .any(|p| path.starts_with(p))
}

fn writes(scope: &Scope, inv: &Invocation, out: &mut Out) {
    for (text, path) in scope.write_targets(inv) {
        if is_block_device(&text) {
            out.push(Finding::new(
                "fs.disk",
                Risk::Critical,
                format!("Writes raw data to disk device {text}"),
            ));
            continue;
        }
        let Some(path) = path else { continue };
        out.facts.paths.push(path.clone());
        if let Some(what) = sensitive_write(&path, scope.home()) {
            out.push(Finding::new(
                "fs.write-sensitive",
                Risk::High,
                format!("Writes {what}: {}", scope.show(&path)),
            ));
        } else if let Some(root) = scope.ctx.project_root.as_deref() {
            if !path.starts_with(root) && !paths::is_temp(&path) {
                out.push(Finding::new(
                    "fs.write-outside-project",
                    Risk::Medium,
                    format!("Writes outside the project: {}", scope.show(&path)),
                ));
            }
        }
    }
}

/// Locations where a write gives persistence or changes how other programs
/// run.
pub(crate) fn sensitive_write(path: &Path, home: Option<&Path>) -> Option<&'static str> {
    let text = path.to_string_lossy();
    let components: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if let Some(i) = components.iter().position(|c| c == ".git") {
        match components.get(i + 1).map(String::as_str) {
            Some("hooks") => return Some("a git hook (runs on every git operation)"),
            Some("config") => return Some("the repository's git config"),
            _ => {}
        }
    }
    if text.starts_with("/etc/") || text == "/etc" {
        return Some("system configuration in /etc");
    }
    if text.starts_with("/Library/LaunchAgents") || text.starts_with("/Library/LaunchDaemons") {
        return Some("a system launch agent");
    }
    if [
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/usr/local/bin/",
        "/usr/lib/",
        "/System/",
    ]
    .iter()
    .any(|p| text.starts_with(p))
    {
        return Some("a system binary location");
    }
    if text.starts_with("/var/spool/cron") {
        return Some("a crontab");
    }
    let home = home?;
    let rel = path.strip_prefix(home).ok()?.to_string_lossy().into_owned();
    const SHELL_RC: &[&str] = &[
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".zlogin",
        ".zlogout",
        ".config/fish/config.fish",
        ".xinitrc",
        ".xprofile",
        ".inputrc",
    ];
    if SHELL_RC.contains(&rel.as_str()) {
        return Some("a shell startup file");
    }
    if rel == ".ssh/authorized_keys"
        || rel == ".ssh/config"
        || rel == ".ssh/rc"
        || rel == ".ssh/environment"
    {
        return Some("SSH configuration");
    }
    if rel == ".gitconfig" || rel == ".config/git/config" {
        return Some("global git config");
    }
    if rel.starts_with("Library/LaunchAgents") {
        return Some("a launch agent (runs at login)");
    }
    if rel.starts_with(".config/autostart") || rel.starts_with(".config/systemd") {
        return Some("an autostart entry");
    }
    None
}
