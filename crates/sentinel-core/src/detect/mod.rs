//! Detectors turn invocations into findings.
//!
//! Each detector looks at one concern (filesystem, git, network, …) and is
//! independent of the others. They share [`Scope`], which resolves words to
//! paths relative to the right working directory.

pub(crate) mod exec;
pub(crate) mod filesystem;
pub(crate) mod git;
pub(crate) mod infra;
pub(crate) mod network;
pub(crate) mod packages;
pub(crate) mod secrets;
pub(crate) mod tamper;

use std::path::{Path, PathBuf};

use crate::command::{CommandSet, Invocation};
use crate::shell::{RedirectKind, Word};
use crate::{paths, Action, AnalysisContext, Facts, Finding};

pub(crate) struct Scope<'a> {
    pub action: &'a Action,
    pub ctx: &'a AnalysisContext,
    pub set: &'a CommandSet,
}

#[derive(Default)]
pub(crate) struct Out {
    pub findings: Vec<Finding>,
    pub facts: Facts,
}

impl Out {
    pub fn push(&mut self, finding: Finding) {
        if !self
            .findings
            .iter()
            .any(|f| f.id == finding.id && f.message == finding.message)
        {
            self.findings.push(finding);
        }
    }
}

/// A path-like argument of an invocation.
#[derive(Debug, Clone)]
pub(crate) struct Operand {
    /// The argument as written (after quote removal).
    pub text: String,
    /// Resolved absolute path, when statically known.
    pub path: Option<PathBuf>,
    pub glob: bool,
    /// Came from `--opt=VALUE` / `--opt VALUE` where opt names an env file.
    pub env_file_option: bool,
}

impl<'a> Scope<'a> {
    pub fn home(&self) -> Option<&Path> {
        self.ctx.home.as_deref()
    }

    pub fn resolve(&self, inv: &Invocation, word: &Word) -> Option<PathBuf> {
        paths::resolve_word(word, inv.cwd.as_deref(), self.home())
    }

    pub fn resolve_text(&self, inv: &Invocation, text: &str) -> Option<PathBuf> {
        let tilde = text.starts_with('~');
        paths::resolve(text, tilde, inv.cwd.as_deref(), self.home())
    }

    /// Short display form: relative to the working directory when inside
    /// it, `~/…` under home, absolute otherwise.
    pub fn show(&self, path: &Path) -> String {
        if let Ok(rel) = path.strip_prefix(&self.action.cwd) {
            if rel.as_os_str().is_empty() {
                return ".".into();
            }
            return format!("./{}", rel.display());
        }
        paths::display(path, self.home())
    }

    /// Path-like arguments. Option values of the form `--opt=VALUE`, `@FILE`
    /// (curl) and `if=`/`of=` (dd) are unpacked. Data arguments of
    /// `echo`/`printf` are not paths.
    pub fn operands(&self, inv: &Invocation) -> Vec<Operand> {
        if matches!(inv.exe.as_str(), "echo" | "printf" | "") {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut options_done = false;
        let mut env_file_next = false;
        for word in inv.args() {
            let raw = word.text.as_str();
            if !options_done && raw == "--" {
                options_done = true;
                continue;
            }
            let mut text = raw.to_string();
            let mut env_file_option = std::mem::take(&mut env_file_next);
            if !options_done && raw.starts_with('-') {
                if raw == "--env-file" || raw == "--env_file" {
                    env_file_next = true;
                    continue;
                }
                match raw.split_once('=') {
                    Some((opt, value)) if opt.starts_with("--") => {
                        env_file_option = opt.contains("env-file") || opt.contains("env_file");
                        text = value.to_string();
                    }
                    _ => continue,
                }
            } else if let Some(rest) = raw.strip_prefix('@') {
                text = rest.to_string();
            } else if let Some((key, value)) = raw.split_once('=') {
                if matches!(key, "if" | "of") {
                    text = value.to_string();
                }
            }
            if text.is_empty() || text == "-" {
                continue;
            }
            let path = if text == raw {
                self.resolve(inv, word)
            } else if word.is_static() {
                self.resolve_text(inv, &text)
            } else {
                None
            };
            out.push(Operand {
                text,
                path,
                glob: word.glob,
                env_file_option,
            });
        }
        out
    }

    /// Files an invocation writes through redirections.
    pub fn redirect_writes(&self, inv: &Invocation) -> Vec<(String, Option<PathBuf>)> {
        inv.redirects
            .iter()
            .filter(|r| {
                matches!(
                    r.kind,
                    RedirectKind::Write | RedirectKind::Append | RedirectKind::ReadWrite
                )
            })
            .map(|r| (r.target.text.clone(), self.resolve(inv, &r.target)))
            .collect()
    }

    /// Files an invocation reads through `<` redirections.
    pub fn redirect_reads(&self, inv: &Invocation) -> Vec<(String, Option<PathBuf>)> {
        inv.redirects
            .iter()
            .filter(|r| matches!(r.kind, RedirectKind::Read | RedirectKind::ReadWrite))
            .map(|r| (r.target.text.clone(), self.resolve(inv, &r.target)))
            .collect()
    }

    /// Files an invocation writes: redirections plus the destination of
    /// common file-writing programs.
    pub fn write_targets(&self, inv: &Invocation) -> Vec<(String, Option<PathBuf>)> {
        let mut out = self.redirect_writes(inv);
        let operands = self.operands(inv);
        let positional: Vec<&Operand> = {
            let pos_texts: Vec<String> = inv.positionals().iter().map(|w| w.text.clone()).collect();
            operands
                .iter()
                .filter(|o| pos_texts.contains(&o.text))
                .collect()
        };
        let mut push = |o: &Operand| out.push((o.text.clone(), o.path.clone()));
        match inv.exe.as_str() {
            "tee" | "touch" | "truncate" => positional.iter().for_each(|o| push(o)),
            "cp" | "mv" | "install" | "ln" | "rsync" => {
                if let Some(t) = option_value(inv, &["-t", "--target-directory"]) {
                    if let Some(o) = operands.iter().find(|o| o.text == t) {
                        push(o);
                    }
                } else if positional.len() >= 2 {
                    push(positional[positional.len() - 1]);
                }
            }
            "sed" | "perl" if inv.has_flag(Some('i'), &["--in-place"]) => {
                let script_given = inv.has_flag(None, &["-e", "-f", "--expression", "--file"]);
                let skip = if script_given || inv.exe == "perl" {
                    0
                } else {
                    1
                };
                positional.iter().skip(skip).for_each(|o| push(o));
            }
            "dd" => operands
                .iter()
                .filter(|o| {
                    inv.args()
                        .iter()
                        .any(|w| w.text == format!("of={}", o.text))
                })
                .for_each(&mut push),
            "curl" | "wget" => {
                if let Some(t) = option_value(inv, &["-o", "--output", "-O", "--output-document"]) {
                    if let Some(o) = operands.iter().find(|o| o.text == t) {
                        push(o);
                    } else {
                        out.push((t.clone(), self.resolve_text(inv, &t)));
                    }
                }
            }
            _ => {}
        }
        out
    }
}

/// Value of the first matching option: `-o VALUE`, `--output=VALUE`.
pub(crate) fn option_value(inv: &Invocation, names: &[&str]) -> Option<String> {
    let args = inv.args();
    for (i, w) in args.iter().enumerate() {
        let t = w.text.as_str();
        if t == "--" {
            break;
        }
        for name in names {
            if t == *name {
                return args.get(i + 1).map(|w| w.text.clone());
            }
            if let Some(v) = t.strip_prefix(&format!("{name}=")) {
                return Some(v.to_string());
            }
            // `-oFILE`
            if name.len() == 2
                && !name.starts_with("--")
                && t.starts_with(name)
                && t.len() > 2
                && !t.starts_with("--")
            {
                return Some(t[2..].to_string());
            }
        }
    }
    None
}

/// Programs that only inspect metadata or never read file contents.
pub(crate) fn is_metadata_only(exe: &str) -> bool {
    matches!(
        exe,
        "ls" | "stat"
            | "test"
            | "["
            | "[["
            | "touch"
            | "chmod"
            | "chown"
            | "chgrp"
            | "rm"
            | "rmdir"
            | "unlink"
            | "shred"
            | "wc"
            | "du"
            | "realpath"
            | "readlink"
            | "basename"
            | "dirname"
            | "mkdir"
            | "cd"
            | "pushd"
            | "which"
            | "type"
            | "file"
            | "mv"
            | "exa"
            | "eza"
            | "tree"
            | "lsof"
            | "getfacl"
            | "xattr"
    )
}

/// Programs whose purpose is to print or copy file contents.
pub(crate) fn reads_content(exe: &str) -> bool {
    matches!(
        exe,
        "cat"
            | "less"
            | "more"
            | "head"
            | "tail"
            | "bat"
            | "batcat"
            | "nl"
            | "tac"
            | "od"
            | "xxd"
            | "hexdump"
            | "strings"
            | "base64"
            | "base32"
            | "grep"
            | "egrep"
            | "fgrep"
            | "rg"
            | "ag"
            | "awk"
            | "gawk"
            | "sed"
            | "cut"
            | "sort"
            | "uniq"
            | "jq"
            | "yq"
            | "cp"
            | "scp"
            | "rsync"
            | "curl"
            | "nc"
            | "ncat"
            | "openssl"
            | "gpg"
            | "tar"
            | "zip"
            | "7z"
            | "diff"
            | "cmp"
            | "vim"
            | "vi"
            | "nano"
            | "emacs"
            | "code"
            | "view"
            | "pbcopy"
            | "xclip"
            | "wl-copy"
    )
}
