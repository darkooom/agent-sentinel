//! "Allow for session" grants.
//!
//! A grant covers one exact action (kind, working directory and target
//! text) in one terminal session, for a limited time. It never covers a
//! rule or a pattern: approving `git push -f origin topic` does not approve
//! `git push -f origin main`.
//!
//! Grants live in the state directory as SHA-256 hashes, so the file does
//! not hold command text. An agent with unrestricted file write access
//! could still forge a grant; sentinel blocks the writes it can see
//! (`sentinel.tamper`), but that is not OS-level protection.

use std::path::PathBuf;

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use sentinel_core::Action;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Paths;

const TTL_HOURS: i64 = 12;

#[derive(Default, Serialize, Deserialize)]
struct Grants {
    grants: Vec<Grant>,
}

#[derive(Serialize, Deserialize)]
struct Grant {
    hash: String,
    expires: DateTime<Utc>,
}

pub struct Sessions {
    file: PathBuf,
    pub key: String,
}

impl Sessions {
    pub fn current(paths: &Paths) -> Sessions {
        let key = session_key();
        Sessions {
            file: paths.sessions_dir().join(format!("{key}.json")),
            key,
        }
    }

    pub fn is_granted(&self, action: &Action) -> bool {
        let hash = fingerprint(action);
        let now = Utc::now();
        self.load()
            .grants
            .iter()
            .any(|g| g.hash == hash && g.expires > now)
    }

    pub fn grant(&self, action: &Action) -> Result<()> {
        let mut grants = self.load();
        let now = Utc::now();
        grants.grants.retain(|g| g.expires > now);
        grants.grants.push(Grant {
            hash: fingerprint(action),
            expires: now + Duration::hours(TTL_HOURS),
        });
        if let Some(dir) = self.file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.file.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&grants)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.file)?;
        Ok(())
    }

    pub fn active_count(&self) -> usize {
        let now = Utc::now();
        self.load()
            .grants
            .iter()
            .filter(|g| g.expires > now)
            .count()
    }

    fn load(&self) -> Grants {
        std::fs::read(&self.file)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
}

fn fingerprint(action: &Action) -> String {
    let mut h = Sha256::new();
    for part in [
        "v1",
        action.kind.as_str(),
        &action.cwd.to_string_lossy(),
        action.target(),
    ] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// `SENTINEL_SESSION` if set; otherwise the terminal session id on Unix.
fn session_key() -> String {
    let raw = std::env::var("SENTINEL_SESSION")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(platform_session);
    let clean: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    if clean.is_empty() {
        "default".into()
    } else {
        clean
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn platform_session() -> String {
    // SAFETY: getsid(0) has no preconditions and only reads process state.
    let sid = unsafe { libc::getsid(0) };
    if sid > 0 {
        format!("sid-{sid}")
    } else {
        "default".into()
    }
}

#[cfg(not(unix))]
fn platform_session() -> String {
    "console".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_are_exact() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config_dir: dir.path().into(),
            state_dir: dir.path().into(),
        };
        let sessions = Sessions {
            file: paths.sessions_dir().join("t.json"),
            key: "t".into(),
        };
        let a = Action::shell("git push -f origin topic", "/w");
        assert!(!sessions.is_granted(&a));
        sessions.grant(&a).unwrap();
        assert!(sessions.is_granted(&a));
        assert!(!sessions.is_granted(&Action::shell("git push -f origin main", "/w")));
        assert!(!sessions.is_granted(&Action::shell("git push -f origin topic", "/other")));
        let raw = std::fs::read_to_string(paths.sessions_dir().join("t.json")).unwrap();
        assert!(
            !raw.contains("git push"),
            "grants must not store command text"
        );
    }
}
