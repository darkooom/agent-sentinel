use std::path::{Component, Path};

/// Why a path is considered to hold secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretPath {
    pub kind: &'static str,
    /// The path is a directory of credentials (`~/.ssh`), not a single file.
    pub directory: bool,
    /// The name alone is not conclusive (`*.pem` may be a public
    /// certificate); inspect the content when possible.
    pub needs_content_check: bool,
}

const fn file(kind: &'static str) -> Option<SecretPath> {
    Some(SecretPath {
        kind,
        directory: false,
        needs_content_check: false,
    })
}

/// Classify a normalized absolute path. `home` enables `~`-relative rules.
pub fn classify_path(path: &Path, home: Option<&Path>) -> Option<SecretPath> {
    let name = path.file_name()?.to_str()?;
    let lower = name.to_ascii_lowercase();

    if let Some(kind) = classify_name(&lower) {
        return Some(kind);
    }

    if path == Path::new("/etc/shadow")
        || path == Path::new("/etc/gshadow")
        || path == Path::new("/etc/master.passwd")
    {
        return file("system password database");
    }

    let home = home?;
    let rel = path.strip_prefix(home).ok()?;
    let parts: Vec<&str> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();
    let under = |dir: &[&str]| parts.len() >= dir.len() && parts[..dir.len()] == *dir;
    let exactly = |dir: &[&str]| parts == dir;

    const DIRS: &[(&[&str], &str)] = &[
        (&[".ssh"], "SSH directory"),
        (&[".aws"], "AWS credentials"),
        (&[".gnupg"], "GnuPG keyring"),
        (&[".config", "gcloud"], "Google Cloud credentials"),
        (&[".azure"], "Azure credentials"),
        (&[".kube"], "Kubernetes credentials"),
        (&[".docker"], "Docker credentials"),
        (&[".password-store"], "password store"),
        (&[".config", "gh"], "GitHub CLI credentials"),
        (&[".config", "op"], "1Password CLI configuration"),
        (&["Library", "Keychains"], "macOS keychain"),
        (&[".terraform.d"], "Terraform credentials"),
    ];
    for (dir, kind) in DIRS {
        if exactly(dir) {
            return Some(SecretPath {
                kind,
                directory: true,
                needs_content_check: false,
            });
        }
        if under(dir) {
            // Public halves and host lists in ~/.ssh are not secrets.
            if dir == &[".ssh"]
                && (lower.ends_with(".pub")
                    || lower.starts_with("known_hosts")
                    || lower == "config"
                    || lower == "authorized_keys")
            {
                return None;
            }
            return file(kind);
        }
    }

    const FILES: &[(&[&str], &str)] = &[
        (&[".claude", ".credentials.json"], "Claude Code credentials"),
        (&[".codex", "auth.json"], "Codex credentials"),
        (&[".cargo", "credentials"], "Cargo registry token"),
        (&[".cargo", "credentials.toml"], "Cargo registry token"),
        (&[".gem", "credentials"], "RubyGems credentials"),
        (&[".config", "hub"], "GitHub credentials"),
        (&[".vault-token"], "Vault token"),
        (&[".boto"], "cloud credentials"),
    ];
    FILES
        .iter()
        .find(|(p, _)| exactly(p))
        .and_then(|(_, kind)| file(kind))
}

fn classify_name(lower: &str) -> Option<SecretPath> {
    // Dotenv files, minus committed templates.
    let is_env = lower == ".env"
        || lower == ".envrc"
        || lower.starts_with(".env.")
        || lower.ends_with(".env");
    if is_env {
        const TEMPLATES: &[&str] = &[
            "example", "sample", "template", "dist", "defaults", "schema", "tpl",
        ];
        let template = TEMPLATES
            .iter()
            .any(|t| lower.ends_with(&format!(".{t}")) || lower.contains(&format!(".{t}.")));
        return if template {
            None
        } else {
            file("environment file")
        };
    }
    match lower {
        "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519" | "id_ecdsa_sk" | "id_ed25519_sk" => {
            return file("SSH private key")
        }
        ".netrc" | "_netrc" => return file("netrc credentials"),
        ".npmrc" => return file("npm configuration (may hold tokens)"),
        ".pypirc" => return file("PyPI credentials"),
        ".git-credentials" => return file("git credentials"),
        ".pgpass" => return file("PostgreSQL password file"),
        ".my.cnf" => return file("MySQL credentials"),
        ".htpasswd" => return file("htpasswd file"),
        ".dockercfg" => return file("Docker credentials"),
        "credentials" | "credentials.json" | "credentials.yml" | "credentials.yaml" => {
            return file("credentials file")
        }
        "secrets.json" | "secrets.yml" | "secrets.yaml" | "secrets.toml" | ".secrets" => {
            return file("secrets file")
        }
        "master.key" => return file("Rails master key"),
        "terraform.tfvars" => return file("Terraform variables"),
        _ => {}
    }
    if lower.starts_with("service-account") && lower.ends_with(".json")
        || lower.starts_with("client_secret") && lower.ends_with(".json")
    {
        return file("cloud service account key");
    }
    if lower.ends_with(".tfstate") || lower.ends_with(".tfstate.backup") {
        return file("Terraform state (contains secrets)");
    }
    const KEY_EXTS: &[&str] = &[".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".ppk"];
    if KEY_EXTS.iter().any(|e| lower.ends_with(e)) {
        return file("key store");
    }
    if lower.ends_with(".pem") || lower.ends_with(".key") {
        return Some(SecretPath {
            kind: "private key",
            directory: false,
            needs_content_check: true,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn classify(p: &str) -> Option<&'static str> {
        classify_path(Path::new(p), Some(Path::new("/home/dev"))).map(|s| s.kind)
    }

    #[test]
    fn dotenv_files() {
        assert!(classify("/p/.env").is_some());
        assert!(classify("/p/.env.local").is_some());
        assert!(classify("/p/config/.env.production").is_some());
        assert!(classify("/p/prod.env").is_some());
        assert!(classify("/p/.env.example").is_none());
        assert!(classify("/p/.env.sample").is_none());
        assert!(classify("/p/.env.template").is_none());
        assert!(classify("/p/environment.ts").is_none());
    }

    #[test]
    fn home_credentials() {
        assert!(classify("/home/dev/.ssh/id_ed25519").is_some());
        assert!(classify("/home/dev/.ssh/work_key").is_some());
        assert!(classify("/home/dev/.ssh/id_ed25519.pub").is_none());
        assert!(classify("/home/dev/.ssh/known_hosts").is_none());
        assert!(classify("/home/dev/.aws/credentials").is_some());
        assert!(classify("/home/dev/.kube/config").is_some());
        assert!(
            classify("/home/dev/.config/gcloud/application_default_credentials.json").is_some()
        );
        let ssh = classify_path(
            &PathBuf::from("/home/dev/.ssh"),
            Some(Path::new("/home/dev")),
        )
        .unwrap();
        assert!(ssh.directory);
    }

    #[test]
    fn ordinary_files() {
        assert!(classify("/p/src/main.rs").is_none());
        assert!(classify("/p/README.md").is_none());
        assert!(classify("/home/dev/.bashrc").is_none());
        assert!(classify("/p/tokens.ts").is_none());
    }
}
