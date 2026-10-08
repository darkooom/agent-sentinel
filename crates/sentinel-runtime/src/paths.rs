use std::path::PathBuf;

/// Where sentinel keeps user-level configuration and state.
///
/// `SENTINEL_HOME` puts both in one directory (used by tests and for
/// portable setups). Otherwise XDG locations are used on every Unix,
/// including macOS, and `%APPDATA%`/`%LOCALAPPDATA%` on Windows.
#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Paths {
    pub fn discover() -> Paths {
        if let Some(home) = std::env::var_os("SENTINEL_HOME").filter(|v| !v.is_empty()) {
            let dir = PathBuf::from(home);
            return Paths {
                config_dir: dir.clone(),
                state_dir: dir,
            };
        }
        let home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let env_dir = |var: &str| {
            std::env::var_os(var)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        if cfg!(windows) {
            let config = env_dir("APPDATA").unwrap_or_else(|| home.join("AppData/Roaming"));
            let state = env_dir("LOCALAPPDATA").unwrap_or_else(|| home.join("AppData/Local"));
            return Paths {
                config_dir: config.join("agent-sentinel"),
                state_dir: state.join("agent-sentinel"),
            };
        }
        Paths {
            config_dir: env_dir("XDG_CONFIG_HOME")
                .unwrap_or_else(|| home.join(".config"))
                .join("agent-sentinel"),
            state_dir: env_dir("XDG_STATE_HOME")
                .unwrap_or_else(|| home.join(".local/state"))
                .join("agent-sentinel"),
        }
    }

    pub fn audit_log(&self) -> PathBuf {
        self.state_dir.join("audit.jsonl")
    }

    pub fn sessions_dir(&self) -> PathBuf {
        self.state_dir.join("sessions")
    }

    pub fn global_policy(&self) -> PathBuf {
        self.config_dir.join("policy.yml")
    }
}
