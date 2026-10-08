//! Running an approved command.

use std::io;
use std::path::PathBuf;
use std::process::Command;

use sentinel_core::command::{is_shell, program_name};
use sentinel_core::shell::quote_argv;

/// What `sentinel run` was asked to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// A single argument: a shell command line, run with `bash -c` (or
    /// `sh -c` where bash is missing).
    Shell(String),
    /// Several arguments: executed directly, no shell involved.
    Argv(Vec<String>),
}

impl Invocation {
    pub fn from_args(args: &[String]) -> Invocation {
        match args {
            [single] => Invocation::Shell(single.clone()),
            many => Invocation::Argv(many.to_vec()),
        }
    }

    /// The text that is analyzed. For argv it is quoted so the parser sees
    /// exactly the words that will be executed.
    pub fn command_line(&self) -> String {
        match self {
            Invocation::Shell(s) => s.clone(),
            Invocation::Argv(argv) => quote_argv(argv),
        }
    }

    /// Starts an interactive shell, inside which sentinel sees nothing.
    pub fn is_interactive_shell(&self) -> bool {
        let argv: Vec<&str> = match self {
            Invocation::Shell(s) => s.split_whitespace().collect(),
            Invocation::Argv(a) => a.iter().map(String::as_str).collect(),
        };
        let Some(first) = argv.first() else {
            return false;
        };
        is_shell(&program_name(first))
            && argv[1..]
                .iter()
                .all(|a| a.starts_with('-') && !a.contains('c'))
    }

    fn command(&self) -> Command {
        match self {
            Invocation::Shell(line) => {
                if cfg!(windows) {
                    let mut c = Command::new("cmd");
                    c.arg("/C").arg(line);
                    c
                } else {
                    let mut c = Command::new(posix_shell());
                    c.arg("-c").arg(line);
                    c
                }
            }
            Invocation::Argv(argv) => {
                let mut c = Command::new(&argv[0]);
                c.args(&argv[1..]);
                c
            }
        }
    }

    /// Run to completion and return the exit code. On Unix, signals map to
    /// 128 + signal like a shell does.
    pub fn run(&self) -> io::Result<i32> {
        let status = self.command().status()?;
        if let Some(code) = status.code() {
            return Ok(code);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = status.signal() {
                return Ok(128 + sig);
            }
        }
        Ok(1)
    }

    /// Replace the current process on Unix so signals and exit codes behave
    /// exactly as if the command were run directly. Falls back to `run`.
    pub fn exec(&self) -> io::Result<i32> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = self.command().exec();
            Err(err)
        }
        #[cfg(not(unix))]
        {
            self.run()
        }
    }
}

fn posix_shell() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join("bash"))
        .find(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("/bin/sh"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_argument_is_a_shell_line() {
        let inv = Invocation::from_args(&["rm -rf ./test".into()]);
        assert_eq!(inv, Invocation::Shell("rm -rf ./test".into()));
        assert_eq!(inv.command_line(), "rm -rf ./test");
    }

    #[test]
    fn argv_is_quoted_for_analysis() {
        let inv = Invocation::from_args(&["echo".into(), "a; rm -rf /".into()]);
        assert_eq!(inv.command_line(), "echo 'a; rm -rf /'");
    }

    #[test]
    fn detects_interactive_shells() {
        assert!(Invocation::from_args(&["bash".into()]).is_interactive_shell());
        assert!(Invocation::from_args(&["zsh".into(), "-l".into()]).is_interactive_shell());
        assert!(
            !Invocation::from_args(&["bash".into(), "-c".into(), "ls".into()])
                .is_interactive_shell()
        );
        assert!(!Invocation::from_args(&["bash script.sh".into()]).is_interactive_shell());
    }
}
