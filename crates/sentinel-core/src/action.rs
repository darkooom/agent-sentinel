use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The kind of operation an agent asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// A shell command line.
    Shell,
    /// Reading a file (or searching inside one).
    FileRead,
    /// Creating or modifying a file.
    FileWrite,
    /// Fetching a URL.
    Network,
    /// Any other agent tool. Only agent/tool matchers apply.
    Tool,
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::Shell => "shell",
            ActionKind::FileRead => "file_read",
            ActionKind::FileWrite => "file_write",
            ActionKind::Network => "network",
            ActionKind::Tool => "tool",
        }
    }
}

/// Something an agent wants to do, normalized across agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub kind: ActionKind,
    /// Shell command line, for `Shell`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Target path, for `FileRead` / `FileWrite`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Target URL, for `Network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Content about to be written, for `FileWrite`. Scanned for secrets,
    /// never logged.
    #[serde(default, skip_serializing)]
    pub content: Option<String>,
    /// Working directory the action runs in.
    pub cwd: PathBuf,
    /// Agent that requested the action (`claude-code`, `codex`, `cli`, …).
    #[serde(default = "default_agent")]
    pub agent: String,
    /// Agent-native tool name (`Bash`, `Read`, …), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Agent session identifier, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

fn default_agent() -> String {
    "unknown".to_string()
}

impl Action {
    fn new(kind: ActionKind, cwd: impl Into<PathBuf>) -> Self {
        Action {
            kind,
            command: None,
            path: None,
            url: None,
            content: None,
            cwd: cwd.into(),
            agent: default_agent(),
            tool: None,
            session: None,
        }
    }

    pub fn shell(command: impl Into<String>, cwd: impl Into<PathBuf>) -> Self {
        let mut action = Action::new(ActionKind::Shell, cwd);
        action.command = Some(command.into());
        action
    }

    pub fn file_read(path: impl Into<String>, cwd: impl Into<PathBuf>) -> Self {
        let mut action = Action::new(ActionKind::FileRead, cwd);
        action.path = Some(path.into());
        action
    }

    pub fn file_write(
        path: impl Into<String>,
        content: Option<String>,
        cwd: impl Into<PathBuf>,
    ) -> Self {
        let mut action = Action::new(ActionKind::FileWrite, cwd);
        action.path = Some(path.into());
        action.content = content;
        action
    }

    pub fn network(url: impl Into<String>, cwd: impl Into<PathBuf>) -> Self {
        let mut action = Action::new(ActionKind::Network, cwd);
        action.url = Some(url.into());
        action
    }

    pub fn tool(name: impl Into<String>, cwd: impl Into<PathBuf>) -> Self {
        let mut action = Action::new(ActionKind::Tool, cwd);
        action.tool = Some(name.into());
        action
    }

    pub fn with_agent(mut self, agent: impl Into<String>) -> Self {
        self.agent = agent.into();
        self
    }

    pub fn with_tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = Some(tool.into());
        self
    }

    pub fn with_session(mut self, session: Option<String>) -> Self {
        self.session = session;
        self
    }

    /// The most descriptive single-line summary of the target: the command,
    /// path, URL or tool name.
    pub fn target(&self) -> &str {
        self.command
            .as_deref()
            .or(self.path.as_deref())
            .or(self.url.as_deref())
            .or(self.tool.as_deref())
            .unwrap_or("")
    }
}
