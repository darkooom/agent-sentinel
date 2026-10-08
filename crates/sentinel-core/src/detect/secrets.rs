use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use globset::Glob;
use regex::Regex;

use super::{is_metadata_only, reads_content, Operand, Out, Scope};
use crate::command::{Executes, Invocation};
use crate::secrets::{classify_path, is_sensitive_name, SecretPath, SecretScanner};
use crate::{Finding, Risk};

/// Largest file sentinel reads to look for secrets, and how much of it.
const MAX_INSPECT_SIZE: u64 = 1024 * 1024;
const INSPECT_BYTES: u64 = 256 * 1024;

/// Names checked when a glob like `.e*` could match a credential file.
const WELL_KNOWN_SECRET_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".envrc",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".pgpass",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials",
    "credentials.json",
    "secrets.yml",
    "secrets.json",
];

pub(crate) fn detect(scope: &Scope, out: &mut Out) {
    let mut env_refs: Vec<String> = Vec::new();
    for inv in &scope.set.invocations {
        env_vars(inv, &mut env_refs, out);
        credential_store(inv, out);
        files(scope, inv, out);
        recursive_search(scope, inv, out);
        if let Some(Executes::InlineCode { interpreter, code }) = &inv.executes {
            inline_code(interpreter, code, &mut env_refs, out);
        }
    }
    if let Some(first) = env_refs.first() {
        out.push(
            Finding::new(
                "secret.env",
                Risk::High,
                format!("References sensitive variable ${first}"),
            )
            .with_details(env_refs.iter().skip(1).map(|v| format!("${v}")).collect()),
        );
    }
    if let Some(command) = &scope.action.command {
        let labels = SecretScanner::builtin().labels(command);
        if let Some(first) = labels.first() {
            out.push(
                Finding::new(
                    "secret.in-command",
                    Risk::High,
                    format!("Command line contains a literal secret ({first})"),
                )
                .with_details(labels.iter().skip(1).cloned().collect()),
            );
        }
    }
}

fn env_vars(inv: &Invocation, refs: &mut Vec<String>, out: &mut Out) {
    let words = inv
        .argv
        .iter()
        .chain(inv.assignments.iter().map(|(_, w)| w))
        .chain(inv.redirects.iter().map(|r| &r.target));
    for word in words {
        for var in &word.vars {
            if !out.facts.env_vars.contains(var) {
                out.facts.env_vars.push(var.clone());
            }
            if is_sensitive_name(var) && !refs.contains(var) {
                refs.push(var.clone());
            }
        }
    }
    let pos: Vec<&str> = inv.positionals().iter().map(|w| w.text.as_str()).collect();
    match inv.exe.as_str() {
        "printenv" if pos.is_empty() => dump(out),
        "printenv" => {
            for name in pos {
                if is_sensitive_name(name) && !refs.contains(&name.to_string()) {
                    refs.push(name.to_string());
                }
            }
        }
        "env"
            if inv.args().is_empty()
                || inv
                    .args()
                    .iter()
                    .all(|w| w.text == "-0" || w.text == "--null") =>
        {
            dump(out)
        }
        "set" if inv.args().is_empty() => dump(out),
        "export" | "declare" | "typeset"
            if inv
                .args()
                .iter()
                .all(|w| matches!(w.text.as_str(), "-p" | "-x" | "-px" | "-xp")) =>
        {
            dump(out)
        }
        _ => {}
    }
}

fn dump(out: &mut Out) {
    out.push(Finding::new(
        "secret.env-dump",
        Risk::High,
        "Prints every environment variable, including secrets",
    ));
}

fn credential_store(inv: &Invocation, out: &mut Out) {
    let pos: Vec<String> = inv
        .positionals()
        .iter()
        .map(|w| w.text.to_ascii_lowercase())
        .collect();
    let has = |a: &str| pos.iter().any(|p| p == a);
    let first = pos.first().map(String::as_str).unwrap_or("");
    let second = pos.get(1).map(String::as_str).unwrap_or("");
    let store = match inv.exe.as_str() {
        "security"
            if matches!(
                first,
                "find-generic-password"
                    | "find-internet-password"
                    | "dump-keychain"
                    | "find-certificate"
            ) =>
        {
            Some("the macOS keychain")
        }
        "op" if matches!(first, "read" | "inject")
            || (first == "item" && second == "get")
            || (first == "document" && second == "get") =>
        {
            Some("1Password")
        }
        "pass" | "gopass"
            if matches!(first, "show" | "cat")
                || (!first.is_empty()
                    && !matches!(
                        first,
                        "ls" | "list"
                            | "find"
                            | "search"
                            | "init"
                            | "insert"
                            | "generate"
                            | "edit"
                            | "rm"
                            | "mv"
                            | "cp"
                            | "git"
                            | "grep"
                    )) =>
        {
            Some("the pass password store")
        }
        "vault" if matches!(first, "read") || (first == "kv" && second == "get") => {
            Some("HashiCorp Vault")
        }
        "aws"
            if (first == "secretsmanager" && second == "get-secret-value")
                || (first == "ssm"
                    && second.starts_with("get-parameter")
                    && inv.has_flag(None, &["--with-decryption"])) =>
        {
            Some("AWS")
        }
        "aws" if first == "configure" && matches!(second, "get" | "export-credentials") => {
            Some("AWS credentials")
        }
        "gcloud" if has("secrets") && has("access") => Some("Google Secret Manager"),
        "gcloud" if has("print-access-token") || has("print-identity-token") => {
            Some("gcloud auth tokens")
        }
        "az" if first == "keyvault" && has("show") => Some("Azure Key Vault"),
        "kubectl" | "oc"
            if first == "get"
                && matches!(second, "secret" | "secrets")
                && inv
                    .args()
                    .iter()
                    .any(|w| w.text.starts_with("-o") || w.text.starts_with("--output")) =>
        {
            Some("Kubernetes secrets")
        }
        "gh" if first == "auth"
            && (second == "token" || inv.has_flag(Some('t'), &["--show-token"])) =>
        {
            Some("the GitHub CLI token")
        }
        "git" if first == "credential" && matches!(second, "fill" | "get") => {
            Some("git's credential helper")
        }
        "doppler" if first == "secrets" => Some("Doppler"),
        "infisical" if matches!(first, "export" | "secrets") => Some("Infisical"),
        "heroku" if first.starts_with("config") => Some("Heroku config vars"),
        "vercel" if first == "env" && second == "pull" => Some("Vercel environment variables"),
        _ => None,
    };
    if let Some(store) = store {
        out.push(Finding::new(
            "secret.store",
            Risk::High,
            format!("Reads secrets from {store}"),
        ));
    }
}

fn files(scope: &Scope, inv: &Invocation, out: &mut Out) {
    let exe = inv.exe.as_str();
    let git_metadata = exe == "git"
        && inv.positionals().first().is_some_and(|s| {
            matches!(
                s.text.as_str(),
                "rm" | "check-ignore" | "ls-files" | "status" | "mv" | "update-index"
            )
        });
    // `$(< .env)` and `done < .env` read a file with no program at all.
    let redirect_only = inv.argv.is_empty();
    if (exe.is_empty() && !redirect_only) || is_metadata_only(exe) || git_metadata {
        return;
    }
    let loads = matches!(exe, "source" | "." | "dotenv" | "dotenvx" | "env-cmd");
    let mut candidates: Vec<Operand> = scope.operands(inv);
    if exe == "git" {
        // `git show HEAD:.env` reads a file from history.
        for w in inv.args() {
            if let Some((rev, path)) = w.text.split_once(':') {
                if !rev.is_empty()
                    && !path.is_empty()
                    && !path.starts_with("//")
                    && !rev.starts_with('-')
                {
                    candidates.push(Operand {
                        text: path.to_string(),
                        path: scope.resolve_text(inv, path),
                        glob: false,
                        env_file_option: false,
                    });
                }
            }
        }
    }
    for (text, path) in scope.redirect_reads(inv) {
        candidates.push(Operand {
            text,
            path,
            glob: false,
            env_file_option: false,
        });
    }
    for operand in candidates {
        let Some(path) = operand.path.clone() else {
            continue;
        };
        out.facts.paths.push(path.clone());
        let matches = if operand.glob {
            expand_glob(scope, &path)
        } else {
            vec![path.clone()]
        };
        for candidate in matches {
            if let Some((shown, secret)) = secret_path(scope, &candidate) {
                if loads || operand.env_file_option {
                    out.push(Finding::new(
                        "secret.load",
                        Risk::Medium,
                        format!("Loads {shown} into the environment"),
                    ));
                    continue;
                }
                let labels = if secret.directory {
                    Vec::new()
                } else {
                    content_labels(scope, &candidate)
                };
                if secret.needs_content_check
                    && candidate.is_file()
                    && labels.is_empty()
                    && scope.ctx.inspect_files
                {
                    continue; // e.g. a public certificate named cert.pem
                }
                let message = if secret.directory {
                    format!("Accesses {shown} ({})", secret.kind)
                } else {
                    format!("Reads {shown} ({})", secret.kind)
                };
                out.push(
                    Finding::new("secret.file", Risk::Critical, message)
                        .with_details(detected(&labels)),
                );
                continue;
            }
            if reads_content(exe) && !operand.glob {
                let labels = content_labels(scope, &candidate);
                if let Some(first) = labels.first() {
                    let shown = scope.show(&candidate);
                    out.push(
                        Finding::new(
                            "secret.content",
                            Risk::High,
                            format!("{shown} contains secrets ({first})"),
                        )
                        .with_details(detected(&labels[1..])),
                    );
                }
            }
        }
    }
}

fn detected(labels: &[String]) -> Vec<String> {
    labels.iter().map(|l| format!("detected: {l}")).collect()
}

/// Classify a path, following symlinks when file inspection is enabled.
fn secret_path(scope: &Scope, path: &Path) -> Option<(String, SecretPath)> {
    let home = scope.home();
    if let Some(secret) = classify_path(path, home) {
        return Some((scope.show(path), secret));
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.contains(['*', '?', '[']) && name.starts_with('.') {
            if let Ok(glob) = Glob::new(name) {
                let m = glob.compile_matcher();
                if let Some(hit) = WELL_KNOWN_SECRET_NAMES.iter().find(|n| m.is_match(n)) {
                    let secret = classify_path(&path.with_file_name(hit), home)?;
                    return Some((format!("{} (matches {hit})", scope.show(path)), secret));
                }
            }
        }
    }
    if scope.ctx.inspect_files {
        if let Ok(real) = std::fs::canonicalize(path) {
            if real != path {
                if let Some(secret) = classify_path(&real, home) {
                    return Some((
                        format!("{} → {}", scope.show(path), scope.show(&real)),
                        secret,
                    ));
                }
            }
        }
    }
    None
}

/// Labels of secrets in a file. Reads at most [`INSPECT_BYTES`].
pub(crate) fn content_labels(scope: &Scope, path: &Path) -> Vec<String> {
    if !scope.ctx.inspect_files {
        return Vec::new();
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return Vec::new();
    };
    if !meta.is_file() || meta.len() > MAX_INSPECT_SIZE {
        return Vec::new();
    }
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    if file.take(INSPECT_BYTES).read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&buf);
    SecretScanner::builtin().labels(&text)
}

fn expand_glob(scope: &Scope, pattern: &Path) -> Vec<PathBuf> {
    let mut out = vec![pattern.to_path_buf()];
    if !scope.ctx.inspect_files {
        return out;
    }
    let (Some(dir), Some(name)) = (
        pattern.parent(),
        pattern.file_name().and_then(|n| n.to_str()),
    ) else {
        return out;
    };
    if dir.to_string_lossy().contains(['*', '?', '[']) {
        return out;
    }
    let Ok(glob) = Glob::new(name) else {
        return out;
    };
    let matcher = glob.compile_matcher();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten().take(2000) {
        let file_name = entry.file_name();
        let Some(n) = file_name.to_str() else {
            continue;
        };
        // Shell globs skip dotfiles unless the pattern starts with a dot.
        if n.starts_with('.') && !name.starts_with('.') {
            continue;
        }
        if matcher.is_match(n) {
            out.push(dir.join(n));
        }
    }
    out
}

/// `grep -r` prints matching lines from every file, including `.env`.
fn recursive_search(scope: &Scope, inv: &Invocation, out: &mut Out) {
    let recursive = match inv.exe.as_str() {
        "grep" | "egrep" | "fgrep" => {
            inv.has_flag(Some('r'), &["--recursive"])
                || inv.has_flag(Some('R'), &["--dereference-recursive"])
        }
        "rg" => inv.has_flag(None, &["--no-ignore", "-uu", "-uuu", "--hidden"]),
        _ => false,
    };
    if !recursive || !scope.ctx.inspect_files {
        return;
    }
    if inv
        .args()
        .iter()
        .any(|w| w.text.contains("--exclude") && w.text.contains(".env"))
    {
        return;
    }
    let mut dirs: Vec<PathBuf> = scope
        .operands(inv)
        .into_iter()
        .filter_map(|o| o.path)
        .filter(|p| p.is_dir())
        .collect();
    if dirs.is_empty() {
        dirs.extend(inv.cwd.clone());
    }
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let found: Vec<String> = entries
            .flatten()
            .take(2000)
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|n| {
                classify_path(&dir.join(n), scope.home())
                    .is_some_and(|s| !s.directory && !s.needs_content_check)
            })
            .collect();
        if let Some(first) = found.first() {
            out.push(
                Finding::new(
                    "secret.content",
                    Risk::High,
                    format!(
                        "Recursive search of {} also prints {first}",
                        scope.show(&dir)
                    ),
                )
                .with_details(found.iter().skip(1).cloned().collect()),
            );
        }
    }
}

fn inline_code(interpreter: &str, code: &str, refs: &mut Vec<String>, out: &mut Out) {
    static SECRET_FILE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?:^|[\s'"/(=`])(\.env(?:\.[\w.-]+)?|id_(?:rsa|ed25519|ecdsa|dsa)|\.aws/credentials|\.ssh/[\w.-]+|\.netrc|\.npmrc|\.git-credentials|\.kube/config)(?:$|[\s'"),;`])"#)
            .expect("valid regex")
    });
    static IDENT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b[A-Z][A-Z0-9_]{2,}\b").expect("valid regex"));
    static ENV_DUMP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?:print|console\.log|puts|p|pp|echo|dump|json\.dumps?|JSON\.stringify)\s*\(?\s*(?:dict\()?(?:os\.environ|process\.env|ENV|%ENV|\$_ENV|getenv\(\))\s*\)?\s*\)?\s*(?:$|[;\n)])")
            .expect("valid regex")
    });
    for caps in SECRET_FILE.captures_iter(code) {
        let hit = &caps[1];
        if hit.ends_with(".example")
            || hit.ends_with(".sample")
            || hit.ends_with(".template")
            || hit.ends_with(".pub")
        {
            continue;
        }
        out.push(Finding::new(
            "secret.file",
            Risk::Critical,
            format!("Inline {interpreter} code accesses {hit}"),
        ));
    }
    for m in IDENT.find_iter(code) {
        let name = m.as_str().to_string();
        if is_sensitive_name(&name) && !refs.contains(&name) {
            refs.push(name);
        }
    }
    if ENV_DUMP.is_match(code) {
        dump(out);
    }
}
