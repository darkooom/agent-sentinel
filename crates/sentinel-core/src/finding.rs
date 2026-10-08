use serde::Serialize;

use crate::Risk;

/// Something a detector noticed about an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable identifier from the [`catalog`], e.g. `git.force-push`.
    pub id: &'static str,
    pub risk: Risk,
    /// One-line human explanation, e.g. "Force push to origin/feature".
    pub message: String,
    /// Extra facts, e.g. names of secrets found in a file. Never secret values.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

impl Finding {
    pub fn new(id: &'static str, risk: Risk, message: impl Into<String>) -> Self {
        debug_assert!(
            catalog()
                .iter()
                .any(|spec| spec.id == id && risk <= spec.max_risk),
            "finding `{id}` at risk {risk} is missing from the catalog or exceeds its max risk"
        );
        Finding {
            id,
            risk,
            message: message.into(),
            details: Vec::new(),
        }
    }

    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.details = details;
        self
    }
}

/// Documentation for a finding id.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct FindingSpec {
    pub id: &'static str,
    /// Highest risk this finding is reported with.
    pub max_risk: Risk,
    pub summary: &'static str,
}

const fn spec(id: &'static str, max_risk: Risk, summary: &'static str) -> FindingSpec {
    FindingSpec {
        id,
        max_risk,
        summary,
    }
}

/// Every finding id sentinel can emit. Policies reference these ids, and
/// policy validation rejects patterns that match none of them.
pub fn catalog() -> &'static [FindingSpec] {
    use Risk::*;
    const CATALOG: &[FindingSpec] = &[
        // filesystem
        spec("fs.delete", High, "Deletes files"),
        spec("fs.recursive-delete", High, "Recursively deletes a directory tree"),
        spec("fs.delete-critical", Critical, "Recursively deletes /, $HOME, the project or a system directory"),
        spec("fs.delete-artifacts", Low, "Deletes regenerable build artifacts (node_modules, target, dist, ...)"),
        spec("fs.permissions", Critical, "Recursive or dangerous permission/ownership change"),
        spec("fs.disk", Critical, "Formats, partitions or writes raw disk devices"),
        spec("fs.write-sensitive", High, "Writes shell startup files, SSH config, git hooks, /etc or autostart locations"),
        spec("fs.write-outside-project", Medium, "Writes a file outside the project directory"),
        spec("fs.write", Medium, "Writes a file inside the project"),
        // git
        spec("git.force-push", High, "Force push (rewrites remote history)"),
        spec("git.protected-branch", Critical, "Force push to, or deletion of, a protected branch"),
        spec("git.push-protected", Medium, "Direct push to a protected branch"),
        spec("git.reset-hard", High, "git reset --hard (discards uncommitted work)"),
        spec("git.clean", High, "git clean -f (deletes untracked files)"),
        spec("git.discard-changes", High, "Discards working tree changes (checkout ., restore ., stash drop)"),
        spec("git.branch-delete", High, "Deletes a branch or remote ref"),
        spec("git.history-rewrite", High, "Rewrites history (rebase, commit --amend, filter-branch, reflog expire)"),
        spec("git.config-exec", Critical, "git configuration that executes arbitrary commands"),
        // execution
        spec("exec.remote-script", Critical, "Downloads and executes code (curl | sh and variants)"),
        spec("exec.pipe-to-shell", High, "Pipes data into a shell or interpreter"),
        spec("exec.obfuscated", Critical, "Command that cannot be statically resolved (dynamic executable, eval, decoding into a shell, parse failure)"),
        spec("exec.privilege", High, "Privilege escalation (sudo, su, doas) or privileged containers"),
        spec("exec.inline-code", Medium, "Runs inline interpreter code (python -c, node -e, ...)"),
        spec("exec.system", Critical, "Shutdown, reboot, killing all processes, disabling system protections, persistence"),
        spec("exec.fork-bomb", Critical, "Fork bomb"),
        // infrastructure
        spec("infra.destructive", Critical, "Destroys infrastructure or data (terraform destroy, kubectl delete, DROP TABLE, ...)"),
        // network
        spec("net.request", Medium, "Network request to a host"),
        spec("net.upload", High, "Uploads a local file to a remote host"),
        spec("net.listen", High, "Opens a network listener, serves files, or exposes a local port publicly"),
        // packages
        spec("pkg.add", High, "Adds a new dependency or installs a package"),
        spec("pkg.install", Low, "Installs dependencies from the project manifest or lockfile"),
        spec("pkg.remote-exec", Medium, "Downloads and runs a package (npx, uvx, dlx, ...)"),
        // secrets
        spec("secret.file", Critical, "Accesses a file that holds credentials (.env, SSH keys, cloud credentials)"),
        spec("secret.content", High, "Accesses content that contains secrets"),
        spec("secret.load", Medium, "Loads a secrets file into the environment without printing it"),
        spec("secret.env", High, "References a sensitive environment variable"),
        spec("secret.env-dump", High, "Dumps all environment variables"),
        spec("secret.store", High, "Reads from a credential store (keychain, 1Password, vault, cloud secrets)"),
        spec("secret.in-command", High, "Command line contains a literal secret"),
        spec("secret.in-content", High, "Content about to be written contains a literal secret"),
        // self-protection
        spec("sentinel.tamper", Critical, "Modifies agent-sentinel's policy, state, or agent hook configuration"),
    ];
    CATALOG
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique_and_namespaced() {
        let mut seen = std::collections::HashSet::new();
        for spec in catalog() {
            assert!(seen.insert(spec.id), "duplicate id {}", spec.id);
            assert!(spec.id.contains('.'), "id {} has no namespace", spec.id);
        }
    }
}
