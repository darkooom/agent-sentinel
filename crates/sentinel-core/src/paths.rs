//! Lexical path handling. Nothing here touches the filesystem.

use std::path::{Component, Path, PathBuf};

use crate::shell::Word;

/// Resolve `.` and `..` lexically. `..` never climbs above the root.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() && !out.has_root() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// Join `text` onto `cwd` (unless absolute), expand a leading `~`, normalize.
/// Returns `None` for relative paths when `cwd` is unknown and for `~user`.
pub fn resolve(
    text: &str,
    tilde: bool,
    cwd: Option<&Path>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    let expanded: PathBuf = if tilde && (text == "~" || text.starts_with("~/")) {
        let home = home?;
        home.join(text.trim_start_matches('~').trim_start_matches('/'))
    } else if tilde && text.starts_with('~') {
        return None;
    } else {
        PathBuf::from(text)
    };
    let joined = if expanded.is_absolute() {
        expanded
    } else {
        cwd?.join(expanded)
    };
    Some(normalize(&joined))
}

/// Resolve a shell word to a path. Words referencing only `$HOME` or `$PWD`
/// are expanded; any other expansion makes the path unknowable (`None`).
pub fn resolve_word(word: &Word, cwd: Option<&Path>, home: Option<&Path>) -> Option<PathBuf> {
    let text = expand_known_vars(word, cwd, home)?;
    resolve(&text, word.tilde, cwd, home)
}

/// Text of a word with `$HOME`/`$PWD` substituted, or `None` if the word
/// depends on anything else.
pub fn expand_known_vars(word: &Word, cwd: Option<&Path>, home: Option<&Path>) -> Option<String> {
    if word.is_static() {
        return Some(word.text.clone());
    }
    if word.substitution || word.brace {
        return None;
    }
    let mut text = word.text.clone();
    for var in &word.vars {
        let value = match var.as_str() {
            "HOME" => home?.to_str()?.to_string(),
            "PWD" => cwd?.to_str()?.to_string(),
            _ => return None,
        };
        text = text
            .replace(&format!("${{{var}}}"), &value)
            .replace(&format!("${var}"), &value);
    }
    Some(text)
}

/// Is `path` equal to or below `base`? Both must be normalized.
pub fn is_within(path: &Path, base: &Path) -> bool {
    path.starts_with(base)
}

/// Display form with the home directory shortened to `~`.
pub fn display(path: &Path, home: Option<&Path>) -> String {
    if let Some(home) = home {
        if let Ok(rest) = path.strip_prefix(home) {
            return if rest.as_os_str().is_empty() {
                "~".to_string()
            } else {
                format!("~/{}", rest.display())
            };
        }
    }
    path.display().to_string()
}

/// Temporary directories that are fine to write anywhere in.
pub fn is_temp(path: &Path) -> bool {
    let tmp = std::env::temp_dir();
    [
        "/tmp",
        "/private/tmp",
        "/var/tmp",
        "/private/var/folders",
        "/var/folders",
        "/dev/null",
    ]
    .iter()
    .any(|p| path.starts_with(p))
        || path.starts_with(normalize(&tmp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_lexically() {
        assert_eq!(normalize(Path::new("/a/./b/../c")), PathBuf::from("/a/c"));
        assert_eq!(normalize(Path::new("/../..")), PathBuf::from("/"));
        assert_eq!(normalize(Path::new("a/../..")), PathBuf::from(".."));
    }

    #[test]
    fn resolves_relative_and_home() {
        let cwd = Path::new("/work/app");
        let home = Path::new("/home/dev");
        assert_eq!(
            resolve("../x", false, Some(cwd), Some(home)),
            Some(PathBuf::from("/work/x"))
        );
        assert_eq!(
            resolve("~/x", true, Some(cwd), Some(home)),
            Some(PathBuf::from("/home/dev/x"))
        );
        assert_eq!(
            resolve("~", true, Some(cwd), Some(home)),
            Some(PathBuf::from("/home/dev"))
        );
        assert_eq!(
            resolve("~", false, Some(cwd), Some(home)),
            Some(PathBuf::from("/work/app/~"))
        );
        assert_eq!(resolve("~root", true, Some(cwd), Some(home)), None);
        assert_eq!(resolve("rel", false, None, Some(home)), None);
    }

    #[test]
    fn expands_only_known_variables() {
        let home = Path::new("/home/dev");
        let mut word = Word::literal("$HOME/.ssh");
        word.vars = vec!["HOME".into()];
        assert_eq!(
            resolve_word(&word, None, Some(home)),
            Some(PathBuf::from("/home/dev/.ssh"))
        );
        let mut word = Word::literal("$TARGET/x");
        word.vars = vec!["TARGET".into()];
        assert_eq!(resolve_word(&word, None, Some(home)), None);
    }
}
