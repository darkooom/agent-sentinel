use std::path::{Path, PathBuf};

use globset::{Glob, GlobBuilder, GlobMatcher};
use regex::Regex;
use sentinel_core::{catalog, Action, ActionKind, Analysis, Risk};

use crate::schema::MatchSpec;
use crate::PolicyError;

/// How list-valued facts are combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Any element matching is enough. Used by deny and confirm rules.
    Any,
    /// Every element must match, and there must be at least one. Used by
    /// allow rules so `npm test && curl … | sh` is not allowed by a rule
    /// written for `npm test`.
    All,
}

pub(crate) struct Subject<'a> {
    pub action: &'a Action,
    pub analysis: &'a Analysis,
    /// Base for relative path patterns: project root, else cwd.
    pub base: &'a Path,
}

#[derive(Debug)]
enum Condition {
    Kind(Vec<ActionKind>),
    Agent(Vec<String>),
    Tool(Vec<String>),
    CommandEquals(Vec<String>),
    CommandPrefix(Vec<String>),
    CommandContains(Vec<String>),
    CommandRegex(Vec<Regex>),
    Executable(Vec<String>),
    Path(Vec<PathPattern>),
    Extension(Vec<String>),
    Git(Vec<String>),
    Host(Vec<String>),
    Env(Vec<GlobMatcher>),
    Finding(Vec<GlobMatcher>),
    Risk(Vec<Risk>),
    MinRisk(Risk),
    Cwd(Vec<PathPattern>),
}

#[derive(Debug)]
pub(crate) struct Matcher {
    conditions: Vec<Condition>,
    finding_globs: Vec<GlobMatcher>,
}

#[derive(Debug)]
struct PathPattern {
    glob: GlobMatcher,
    anchor: Anchor,
}

#[derive(Debug, Clone, Copy)]
enum Anchor {
    /// No `/` in the pattern: matches the file name anywhere.
    Name,
    /// Starts with `/` or `~`: matches the absolute path.
    Absolute,
    /// Contains `/`: relative to the project root.
    Relative,
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn glob(pattern: &str, rule: &str) -> Result<GlobMatcher, PolicyError> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| PolicyError::invalid(rule, format!("invalid glob `{pattern}`: {e}")))
}

fn path_pattern(raw: &str, rule: &str) -> Result<PathPattern, PolicyError> {
    let expanded = match (raw.strip_prefix("~/"), std::env::home_dir()) {
        (Some(rest), Some(home)) => format!("{}/{rest}", home.display()),
        _ if raw == "~" => std::env::home_dir()
            .map(|h| h.display().to_string())
            .unwrap_or_else(|| raw.to_string()),
        _ => raw.to_string(),
    };
    let anchor = if expanded.starts_with('/') {
        Anchor::Absolute
    } else if expanded.contains('/') {
        Anchor::Relative
    } else {
        Anchor::Name
    };
    let pattern = expanded.trim_start_matches("./").to_string();
    Ok(PathPattern {
        glob: glob(&pattern, rule)?,
        anchor,
    })
}

impl PathPattern {
    fn matches(&self, path: &Path, base: &Path) -> bool {
        match self.anchor {
            Anchor::Name => path.file_name().is_some_and(|n| self.glob.is_match(n)),
            Anchor::Absolute => self.glob.is_match(path),
            Anchor::Relative => path
                .strip_prefix(base)
                .is_ok_and(|rel| self.glob.is_match(rel)),
        }
    }
}

impl Matcher {
    pub fn compile(spec: &MatchSpec, rule: &str) -> Result<Matcher, PolicyError> {
        let mut conditions = Vec::new();
        let mut finding_globs = Vec::new();
        let lower = |v: Vec<String>| {
            v.into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect::<Vec<_>>()
        };

        if let Some(v) = &spec.kind {
            conditions.push(Condition::Kind(v.to_vec()));
        }
        if let Some(v) = &spec.agent {
            conditions.push(Condition::Agent(lower(v.to_vec())));
        }
        if let Some(v) = &spec.tool {
            conditions.push(Condition::Tool(v.to_vec()));
        }
        if let Some(v) = &spec.command_equals {
            conditions.push(Condition::CommandEquals(
                v.to_vec().iter().map(|s| normalize_ws(s)).collect(),
            ));
        }
        if let Some(v) = &spec.command_prefix {
            conditions.push(Condition::CommandPrefix(
                v.to_vec().iter().map(|s| normalize_ws(s)).collect(),
            ));
        }
        if let Some(v) = &spec.command_contains {
            conditions.push(Condition::CommandContains(
                v.to_vec().iter().map(|s| normalize_ws(s)).collect(),
            ));
        }
        if let Some(v) = &spec.command_regex {
            let regexes = v
                .to_vec()
                .iter()
                .map(|r| {
                    Regex::new(r).map_err(|e| {
                        PolicyError::invalid(rule, format!("invalid regex `{r}`: {e}"))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            conditions.push(Condition::CommandRegex(regexes));
        }
        if let Some(v) = &spec.executable {
            conditions.push(Condition::Executable(lower(v.to_vec())));
        }
        if let Some(v) = &spec.path {
            let patterns = v
                .to_vec()
                .iter()
                .map(|p| path_pattern(p, rule))
                .collect::<Result<Vec<_>, _>>()?;
            conditions.push(Condition::Path(patterns));
        }
        if let Some(v) = &spec.extension {
            conditions.push(Condition::Extension(
                lower(v.to_vec())
                    .into_iter()
                    .map(|e| e.trim_start_matches('.').to_string())
                    .collect(),
            ));
        }
        if let Some(v) = &spec.git {
            conditions.push(Condition::Git(lower(v.to_vec())));
        }
        if let Some(v) = &spec.host {
            let hosts = lower(v.to_vec());
            for h in &hosts {
                if h.contains("://") || h.contains('/') {
                    return Err(PolicyError::invalid(rule, format!("host `{h}` must be a hostname like `example.com` or `*.example.com`, not a URL")));
                }
            }
            conditions.push(Condition::Host(hosts));
        }
        if let Some(v) = &spec.env {
            let globs = v
                .to_vec()
                .iter()
                .map(|p| glob(p, rule))
                .collect::<Result<Vec<_>, _>>()?;
            conditions.push(Condition::Env(globs));
        }
        if let Some(v) = &spec.finding {
            for pattern in v.to_vec() {
                let g = glob(&pattern, rule)?;
                if !catalog().iter().any(|s| g.is_match(s.id)) {
                    return Err(PolicyError::invalid(rule, format!("finding `{pattern}` matches no known finding (see `sentinel policy findings`)")));
                }
                finding_globs.push(g);
            }
            conditions.push(Condition::Finding(finding_globs.clone()));
        }
        if let Some(v) = &spec.risk {
            conditions.push(Condition::Risk(v.to_vec()));
        }
        if let Some(r) = spec.min_risk {
            conditions.push(Condition::MinRisk(r));
        }
        if let Some(v) = &spec.cwd {
            let patterns = v
                .to_vec()
                .iter()
                .map(|p| path_pattern(p, rule))
                .collect::<Result<Vec<_>, _>>()?;
            conditions.push(Condition::Cwd(patterns));
        }
        if conditions.is_empty() {
            return Err(PolicyError::invalid(rule, "`match` has no conditions and would match everything; use the top-level `default` instead"));
        }
        Ok(Matcher {
            conditions,
            finding_globs,
        })
    }

    pub fn matches(&self, s: &Subject, mode: Mode) -> bool {
        self.conditions.iter().all(|c| condition(c, s, mode))
    }

    /// Message of the most severe finding this rule's `finding` condition
    /// matched, used as the decision reason when a rule has none.
    pub fn evidence<'a>(&self, analysis: &'a Analysis) -> Option<&'a str> {
        analysis
            .findings
            .iter()
            .find(|f| self.finding_globs.iter().any(|g| g.is_match(f.id)))
            .map(|f| f.message.as_str())
    }
}

fn combine<T>(items: &[T], mode: Mode, pred: impl Fn(&T) -> bool) -> bool {
    match mode {
        Mode::Any => items.iter().any(pred),
        Mode::All => !items.is_empty() && items.iter().all(pred),
    }
}

fn condition(c: &Condition, s: &Subject, mode: Mode) -> bool {
    let facts = &s.analysis.facts;
    let commands: Vec<String> = facts
        .commands
        .iter()
        .map(|c| normalize_ws(&c.text))
        .collect();
    let raw = s.action.command.as_deref().map(normalize_ws);
    match c {
        Condition::Kind(kinds) => kinds.contains(&s.action.kind),
        Condition::Agent(agents) => agents
            .iter()
            .any(|a| *a == s.action.agent.to_ascii_lowercase()),
        Condition::Tool(tools) => s
            .action
            .tool
            .as_ref()
            .is_some_and(|t| tools.iter().any(|x| x == t)),
        Condition::CommandEquals(values) => {
            raw.as_ref().is_some_and(|r| values.contains(r))
                || combine(&commands, mode, |c| values.contains(c))
        }
        Condition::CommandPrefix(values) => {
            let starts = |text: &str| {
                values
                    .iter()
                    .any(|p| text == p || text.starts_with(&format!("{p} ")))
            };
            (mode == Mode::Any && raw.as_deref().is_some_and(starts))
                || combine(&commands, mode, |c| starts(c))
        }
        Condition::CommandContains(values) => {
            let contains = |text: &str| values.iter().any(|v| text.contains(v.as_str()));
            (mode == Mode::Any && raw.as_deref().is_some_and(contains))
                || combine(&commands, mode, |c| contains(c))
        }
        Condition::CommandRegex(regexes) => {
            let is_match = |text: &str| regexes.iter().any(|r| r.is_match(text));
            (mode == Mode::Any && raw.as_deref().is_some_and(is_match))
                || combine(&commands, mode, |c| is_match(c))
        }
        Condition::Executable(names) => combine(&facts.commands, mode, |c| names.contains(&c.exe)),
        Condition::Path(patterns) => combine(&facts.paths, mode, |p| {
            patterns.iter().any(|pat| pat.matches(p, s.base))
        }),
        Condition::Extension(exts) => combine(&facts.paths, mode, |p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| exts.contains(&e.to_ascii_lowercase()))
        }),
        Condition::Git(subs) => combine(&facts.git_subcommands, mode, |g| {
            subs.contains(&g.to_ascii_lowercase())
        }),
        Condition::Host(patterns) => combine(&facts.hosts, mode, |h| {
            patterns.iter().any(|p| host_matches(p, &h.name))
        }),
        Condition::Env(globs) => combine(&facts.env_vars, mode, |v| {
            globs.iter().any(|g| g.is_match(v))
        }),
        Condition::Finding(globs) => combine(&s.analysis.findings, mode, |f| {
            globs.iter().any(|g| g.is_match(f.id))
        }),
        Condition::Risk(levels) => levels.contains(&s.analysis.risk),
        Condition::MinRisk(level) => s.analysis.risk >= *level,
        Condition::Cwd(patterns) => {
            let cwd: PathBuf = s.action.cwd.clone();
            patterns
                .iter()
                .any(|p| p.matches(&cwd, s.base) || p.glob.is_match(&cwd))
        }
    }
}

/// `example.com` matches exactly; `*.example.com` matches any subdomain
/// (not the apex); `*` matches everything.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if pattern == "*" {
        return true;
    }
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
        None => host == pattern,
    }
}

/// Validate a glob outside of a rule (used for protected branches).
pub(crate) fn validate_glob(pattern: &str, what: &str) -> Result<(), PolicyError> {
    Glob::new(pattern)
        .map(|_| ())
        .map_err(|e| PolicyError::invalid(what, format!("invalid pattern `{pattern}`: {e}")))
}
