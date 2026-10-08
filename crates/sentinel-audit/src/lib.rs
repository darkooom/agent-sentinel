//! Audit log: one JSON object per line, appended for every evaluated action.
//!
//! Commands are redacted before they are written. File contents are never
//! written. The log is created with owner-only permissions and appended
//! under an exclusive file lock, so concurrent hook processes do not
//! interleave lines.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local, SecondsFormat, Utc};
use sentinel_core::{secrets, Action, Risk};
use sentinel_policy::{Decision, Verdict};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

/// What actually happened, as opposed to what the policy said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Allowed by policy.
    Allowed,
    /// Denied by policy.
    Denied,
    /// Needed confirmation; the user allowed it once.
    AllowedOnce,
    /// Needed confirmation; allowed by a grant for this session.
    AllowedSession,
    /// Needed confirmation; the user said no.
    DeniedByUser,
    /// Needed confirmation, but there was no terminal to ask on.
    DeniedNoTerminal,
    /// Handed to the agent's own permission prompt (Claude Code `ask`).
    Asked,
    /// Evaluation only (`sentinel check`); nothing was executed.
    Checked,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::Denied => "denied",
            Outcome::AllowedOnce => "allowed_once",
            Outcome::AllowedSession => "allowed_session",
            Outcome::DeniedByUser => "denied_by_user",
            Outcome::DeniedNoTerminal => "denied_no_terminal",
            Outcome::Asked => "asked",
            Outcome::Checked => "checked",
        }
    }

    /// The action did not run.
    pub fn is_denied(self) -> bool {
        matches!(
            self,
            Outcome::Denied | Outcome::DeniedByUser | Outcome::DeniedNoTerminal
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub v: u32,
    pub timestamp: DateTime<Utc>,
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub cwd: String,
    pub risk: Risk,
    pub decision: Verdict,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<String>,
    pub duration_ms: u64,
}

impl AuditEvent {
    /// Build an event. Secrets in the command, path and URL are redacted
    /// here, so no caller can forget to.
    pub fn new(
        action: &Action,
        decision: &Decision,
        findings: Vec<String>,
        outcome: Outcome,
        duration_ms: u64,
    ) -> Self {
        AuditEvent {
            v: SCHEMA_VERSION,
            timestamp: Utc::now(),
            agent: action.agent.clone(),
            session: action.session.clone(),
            tool: action.tool.clone(),
            action: action.kind.as_str().to_string(),
            command: action.command.as_deref().map(secrets::redact),
            path: action.path.as_deref().map(secrets::redact),
            url: action.url.as_deref().map(secrets::redact),
            cwd: action.cwd.display().to_string(),
            risk: decision.risk,
            decision: decision.verdict,
            outcome,
            rule: decision.rule.clone(),
            reason: secrets::redact(&decision.reason),
            findings,
            duration_ms,
        }
    }

    pub fn target(&self) -> &str {
        self.command
            .as_deref()
            .or(self.path.as_deref())
            .or(self.url.as_deref())
            .or(self.tool.as_deref())
            .unwrap_or("")
    }

    pub fn to_json_line(&self) -> String {
        let mut value = serde_json::to_value(self).expect("audit event serializes");
        // Millisecond precision keeps lines short and sortable.
        value["timestamp"] =
            serde_json::Value::String(self.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true));
        serde_json::to_string(&value).expect("audit event serializes")
    }
}

/// An append-only JSONL audit log.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        AuditLog { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, event: &AuditEvent) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            create_private_dir(dir)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.path)?;
        file.lock()?;
        let mut line = event.to_json_line();
        line.push('\n');
        let result = file.write_all(line.as_bytes()).and_then(|_| file.flush());
        let _ = file.unlock();
        result
    }

    /// All readable events, oldest first. Malformed lines are skipped and
    /// counted.
    pub fn read(&self) -> io::Result<(Vec<AuditEvent>, usize)> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(e) => return Err(e),
        };
        let mut events = Vec::new();
        let mut malformed = 0;
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEvent>(&line) {
                Ok(e) => events.push(e),
                Err(_) => malformed += 1,
            }
        }
        Ok((events, malformed))
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Selection for `sentinel log`.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Only events from the local calendar day.
    pub today: bool,
    /// Only actions that did not run.
    pub denied: bool,
    pub agent: Option<String>,
    /// Keep the most recent N after filtering.
    pub limit: Option<usize>,
}

pub fn filter(events: Vec<AuditEvent>, f: &Filter) -> Vec<AuditEvent> {
    let today = Local::now().date_naive();
    let mut out: Vec<AuditEvent> = events
        .into_iter()
        .filter(|e| !f.today || e.timestamp.with_timezone(&Local).date_naive() == today)
        .filter(|e| !f.denied || e.outcome.is_denied())
        .filter(|e| {
            f.agent
                .as_ref()
                .is_none_or(|a| e.agent.eq_ignore_ascii_case(a))
        })
        .collect();
    if let Some(limit) = f.limit {
        let skip = out.len().saturating_sub(limit);
        out.drain(..skip);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_policy::RuleMatch;

    fn decision(verdict: Verdict) -> Decision {
        Decision {
            verdict,
            rule: Some("block-recursive-delete".into()),
            reason: "Dangerous recursive deletion".into(),
            risk: Risk::High,
            matched: vec![RuleMatch {
                rule: "block-recursive-delete".into(),
                verdict,
            }],
        }
    }

    #[test]
    fn appends_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("nested/audit.jsonl"));
        let action = Action::shell("rm -rf ./test", "/work").with_agent("claude-code");
        let event = AuditEvent::new(
            &action,
            &decision(Verdict::Deny),
            vec!["fs.recursive-delete".into()],
            Outcome::Denied,
            3,
        );
        log.append(&event).unwrap();
        log.append(&event).unwrap();
        let (events, malformed) = log.read().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(malformed, 0);
        assert_eq!(events[0].command.as_deref(), Some("rm -rf ./test"));
        assert_eq!(events[0].decision, Verdict::Deny);
        let raw = std::fs::read_to_string(log.path()).unwrap();
        let first: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(first["action"], "shell");
        assert_eq!(first["outcome"], "denied");
        assert_eq!(first["risk"], "high");
        assert!(first["timestamp"].as_str().unwrap().ends_with('Z'));
    }

    #[cfg(unix)]
    #[test]
    fn log_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("state/audit.jsonl"));
        let action = Action::shell("ls", "/work");
        log.append(&AuditEvent::new(
            &action,
            &decision(Verdict::Allow),
            vec![],
            Outcome::Allowed,
            0,
        ))
        .unwrap();
        let mode = std::fs::metadata(log.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = std::fs::metadata(dir.path().join("state"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }

    #[test]
    fn secrets_are_redacted() {
        let token = format!("ghp_{}", "a1B2c3D4e5".repeat(4));
        let action = Action::shell(
            format!("git clone https://x:{token}@github.com/o/r"),
            "/work",
        );
        let event = AuditEvent::new(
            &action,
            &decision(Verdict::Allow),
            vec![],
            Outcome::Allowed,
            0,
        );
        let line = event.to_json_line();
        assert!(!line.contains(&token), "{line}");
        assert!(line.contains("[REDACTED]"));
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "not json\n\n").unwrap();
        let log = AuditLog::new(&path);
        let action = Action::shell("ls", "/work");
        log.append(&AuditEvent::new(
            &action,
            &decision(Verdict::Allow),
            vec![],
            Outcome::Allowed,
            0,
        ))
        .unwrap();
        let (events, malformed) = log.read().unwrap();
        assert_eq!((events.len(), malformed), (1, 1));
    }

    #[test]
    fn filters() {
        let action = Action::shell("ls", "/work").with_agent("codex");
        let mut old = AuditEvent::new(
            &action,
            &decision(Verdict::Allow),
            vec![],
            Outcome::Allowed,
            0,
        );
        old.timestamp = Utc::now() - chrono::Duration::days(3);
        let denied = AuditEvent::new(
            &action,
            &decision(Verdict::Confirm),
            vec![],
            Outcome::DeniedByUser,
            0,
        );
        let other = AuditEvent::new(
            &Action::shell("ls", "/w").with_agent("cli"),
            &decision(Verdict::Allow),
            vec![],
            Outcome::Allowed,
            0,
        );
        let all = vec![old, denied, other];
        assert_eq!(
            filter(
                all.clone(),
                &Filter {
                    today: true,
                    ..Filter::default()
                }
            )
            .len(),
            2
        );
        assert_eq!(
            filter(
                all.clone(),
                &Filter {
                    denied: true,
                    ..Filter::default()
                }
            )
            .len(),
            1
        );
        assert_eq!(
            filter(
                all.clone(),
                &Filter {
                    agent: Some("CODEX".into()),
                    ..Filter::default()
                }
            )
            .len(),
            2
        );
        let last = filter(
            all,
            &Filter {
                limit: Some(1),
                ..Filter::default()
            },
        );
        assert_eq!(last[0].agent, "cli");
    }
}
