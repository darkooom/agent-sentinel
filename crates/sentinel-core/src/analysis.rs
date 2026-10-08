use std::path::PathBuf;

use serde::Serialize;

use crate::command::{self, CommandSet};
use crate::detect::{self, filesystem, network, secrets as secret_detect, tamper, Out, Scope};
use crate::secrets::{classify_path, SecretScanner};
use crate::{paths, Action, ActionKind, AnalysisContext, Finding, Risk};

/// A network destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Host {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// One simple command, as policies see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandFact {
    /// Canonical text (`git push -f origin main`).
    pub text: String,
    /// Program basename, lowercased; empty if dynamic.
    pub exe: String,
}

/// What an action touches. Policies match against these.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Facts {
    pub commands: Vec<CommandFact>,
    pub paths: Vec<PathBuf>,
    pub hosts: Vec<Host>,
    pub env_vars: Vec<String>,
    pub git_subcommands: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    /// Findings, most severe first.
    pub findings: Vec<Finding>,
    /// Highest finding risk, `low` if none.
    pub risk: Risk,
    pub facts: Facts,
}

impl Analysis {
    pub fn has(&self, id: &str) -> bool {
        self.findings.iter().any(|f| f.id == id)
    }
}

/// Analyze an action. Pure apart from bounded reads of files the action
/// references (when `ctx.inspect_files` is set).
pub fn analyze(action: &Action, ctx: &AnalysisContext) -> Analysis {
    let mut out = Out::default();
    match action.kind {
        ActionKind::Shell => {
            let command = action.command.as_deref().unwrap_or("");
            let set = command::extract(command, &action.cwd, ctx.home.as_deref());
            shell(action, ctx, &set, &mut out);
        }
        ActionKind::FileRead => file_read(action, ctx, &mut out),
        ActionKind::FileWrite => file_write(action, ctx, &mut out),
        ActionKind::Network => {
            if let Some(host) = action.url.as_deref().and_then(network::parse_host) {
                network::add_host(host, &mut out);
            }
        }
        ActionKind::Tool => {}
    }
    finish(out)
}

fn finish(mut out: Out) -> Analysis {
    out.findings.sort_by_key(|f| std::cmp::Reverse(f.risk));
    out.facts.paths.sort();
    out.facts.paths.dedup();
    let risk = out
        .findings
        .iter()
        .map(|f| f.risk)
        .max()
        .unwrap_or_default();
    Analysis {
        findings: out.findings,
        risk,
        facts: out.facts,
    }
}

fn shell(action: &Action, ctx: &AnalysisContext, set: &CommandSet, out: &mut Out) {
    let scope = Scope { action, ctx, set };
    for inv in &set.invocations {
        if inv.argv.is_empty() {
            continue;
        }
        out.facts.commands.push(crate::CommandFact {
            text: inv.canonical(),
            exe: inv.exe.clone(),
        });
    }
    detect::exec::detect(&scope, out);
    detect::filesystem::detect(&scope, out);
    detect::git::detect(&scope, out);
    detect::network::detect(&scope, out);
    detect::packages::detect(&scope, out);
    detect::secrets::detect(&scope, out);
    detect::infra::detect(&scope, out);
    detect::tamper::detect(&scope, out);
}

fn resolve_action_path(action: &Action, ctx: &AnalysisContext) -> Option<PathBuf> {
    let text = action.path.as_deref()?;
    paths::resolve(
        text,
        text.starts_with('~'),
        Some(&action.cwd),
        ctx.home.as_deref(),
    )
}

fn file_read(action: &Action, ctx: &AnalysisContext, out: &mut Out) {
    let Some(path) = resolve_action_path(action, ctx) else {
        return;
    };
    out.facts.paths.push(path.clone());
    // Reuse the shell path logic by analyzing the equivalent `cat`.
    let quoted = crate::shell::quote_word(&path.to_string_lossy());
    let set = command::extract(&format!("cat {quoted}"), &action.cwd, ctx.home.as_deref());
    let scope = Scope {
        action,
        ctx,
        set: &set,
    };
    let mut inner = Out::default();
    secret_detect::detect(&scope, &mut inner);
    for f in inner.findings {
        if f.id != "secret.in-command" {
            out.push(f);
        }
    }
}

fn file_write(action: &Action, ctx: &AnalysisContext, out: &mut Out) {
    let Some(path) = resolve_action_path(action, ctx) else {
        return;
    };
    out.facts.paths.push(path.clone());
    let set = CommandSet::default();
    let scope = Scope {
        action,
        ctx,
        set: &set,
    };
    let shown = scope.show(&path);

    if let Some(what) = tamper::protected(&path, &ctx.protected_paths) {
        out.push(Finding::new(
            "sentinel.tamper",
            Risk::Critical,
            format!("Modifies {what}: {shown}"),
        ));
    }
    if let Some(what) = filesystem::sensitive_write(&path, ctx.home.as_deref()) {
        out.push(Finding::new(
            "fs.write-sensitive",
            Risk::High,
            format!("Writes {what}: {shown}"),
        ));
    }
    let outside = ctx
        .project_root
        .as_deref()
        .is_some_and(|root| !path.starts_with(root) && !paths::is_temp(&path));
    if outside {
        out.push(Finding::new(
            "fs.write-outside-project",
            Risk::Medium,
            format!("Writes outside the project: {shown}"),
        ));
    } else {
        out.push(Finding::new(
            "fs.write",
            Risk::Medium,
            format!("Writes {shown}"),
        ));
    }
    // Secrets belong in secret files; anywhere else they are a leak.
    if let Some(content) = &action.content {
        if classify_path(&path, ctx.home.as_deref()).is_none() {
            let labels = SecretScanner::builtin().labels(content);
            if let Some(first) = labels.first() {
                out.push(
                    Finding::new(
                        "secret.in-content",
                        Risk::High,
                        format!("Writes a literal secret ({first}) into {shown}"),
                    )
                    .with_details(labels.iter().skip(1).cloned().collect()),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
