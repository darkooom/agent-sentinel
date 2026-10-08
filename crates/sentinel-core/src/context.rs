use std::path::PathBuf;

/// Environment an action is analyzed in.
#[derive(Debug, Clone, Default)]
pub struct AnalysisContext {
    /// Home directory, used for `~` and `$HOME` and for recognizing
    /// credential locations.
    pub home: Option<PathBuf>,
    /// Root of the project the agent works in (directory holding
    /// `.sentinel/`, or the git root). Writes outside it are reported.
    pub project_root: Option<PathBuf>,
    /// Branch patterns (globs) that must not be force-pushed or deleted.
    pub protected_branches: Vec<String>,
    /// Extra paths sentinel must protect from modification (its own config
    /// and state directories).
    pub protected_paths: Vec<PathBuf>,
    /// Allow reading files referenced by an action (bounded) to look for
    /// secrets and resolve symlinks. On by default in the runtime.
    pub inspect_files: bool,
}

impl AnalysisContext {
    pub fn new() -> Self {
        AnalysisContext {
            home: std::env::home_dir(),
            project_root: None,
            protected_branches: vec!["main".into(), "master".into()],
            protected_paths: Vec::new(),
            inspect_files: true,
        }
    }
}
