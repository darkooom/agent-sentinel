//! From parsed shell syntax to the commands that will actually run.
//!
//! The parser gives simple commands. This module resolves what executes:
//! it strips wrappers (`sudo`, `env`, `nice`, `timeout`, `xargs`, …), follows
//! nested command text (`bash -c`, `eval`, heredocs into shells, `find -exec`,
//! `ssh host cmd`, `os.system("…")` in inline code), and tracks `cd` so
//! relative paths resolve against the right directory.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::paths;
use crate::shell::{self, Issue, Redirect, RedirectKind, Script, SimpleCommand, Word};

/// How an invocation was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Direct,
    /// `bash -c '…'`, `su -c`, `watch '…'`
    ShellString,
    /// `eval …`
    Eval,
    /// Script fed on stdin (heredoc, here-string, `echo … | sh`)
    Stdin,
    /// `find … -exec …`
    FindExec,
    /// `git -c alias.x='!…'`
    GitAlias,
    /// `ssh host '…'`: runs on another machine
    Remote,
    /// `os.system("…")` and similar inside inline interpreter code
    InlineCode,
}

/// What code an invocation executes besides its own program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Executes {
    /// A shell or interpreter running a script read from stdin.
    Stdin { resolved: bool },
    /// `sh -c STRING`
    ShellString(Word),
    /// `bash FILE`, `python FILE`, `source FILE`
    ScriptFile(Word),
    /// `python -c CODE`, `node -e CODE`, `awk PROGRAM`
    InlineCode { interpreter: String, code: String },
    /// `eval …`
    Eval { resolved: bool },
}

#[derive(Debug, Clone)]
pub struct Invocation {
    /// Effective argv after wrappers are removed. `argv[0]` is the program.
    pub argv: Vec<Word>,
    /// Lowercased basename of the program (`/usr/bin/RM` → `rm`); empty when
    /// the program is not statically known.
    pub exe: String,
    /// Wrappers removed from the front, outermost first.
    pub wrappers: Vec<String>,
    pub assignments: Vec<(String, Word)>,
    pub redirects: Vec<Redirect>,
    pub stdin_piped: bool,
    /// Pipeline this invocation belongs to, and its position in it.
    pub group: usize,
    pub position: usize,
    pub origin: Origin,
    /// Working directory the invocation runs in, if known.
    pub cwd: Option<PathBuf>,
    /// Arguments are appended at runtime (`xargs`, `find -exec {}`).
    pub dynamic_args: bool,
    pub executes: Option<Executes>,
}

impl Invocation {
    pub fn args(&self) -> &[Word] {
        self.argv.get(1..).unwrap_or(&[])
    }

    /// The program word is dynamic (`$cmd`, `$(…)`, `{a,b}`).
    pub fn exe_dynamic(&self) -> bool {
        self.argv.first().is_some_and(|w| !w.is_static())
    }

    /// Normalized single-line text: assignments, program basename, args,
    /// redirections, joined with single spaces.
    pub fn canonical(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for (name, value) in &self.assignments {
            parts.push(format!("{name}={}", value.text));
        }
        parts.extend(self.wrappers.iter().cloned());
        for (i, word) in self.argv.iter().enumerate() {
            if i == 0 && word.is_static() {
                parts.push(program_name(&word.text));
            } else {
                parts.push(word.text.clone());
            }
        }
        for r in &self.redirects {
            let op = match r.kind {
                RedirectKind::Read => "<",
                RedirectKind::Write => ">",
                RedirectKind::Append => ">>",
                RedirectKind::ReadWrite => "<>",
                RedirectKind::Dup => ">&",
                RedirectKind::Heredoc => "<<",
                RedirectKind::HereString => "<<<",
            };
            parts.push(format!("{op}{}", r.target.text));
        }
        parts.join(" ")
    }

    /// Positional (non-option) static arguments, honoring `--`.
    pub fn positionals(&self) -> Vec<&Word> {
        let mut out = Vec::new();
        let mut options_done = false;
        for w in self.args() {
            if !options_done && w.is_static() && w.text == "--" {
                options_done = true;
                continue;
            }
            if !options_done && w.text.starts_with('-') && w.text.len() > 1 {
                continue;
            }
            out.push(w);
        }
        out
    }

    /// Does any short-option cluster contain `short`, or any arg equal one of
    /// `long`? Stops at `--`.
    pub fn has_flag(&self, short: Option<char>, long: &[&str]) -> bool {
        for w in self.args() {
            let t = w.text.as_str();
            if t == "--" {
                break;
            }
            if long
                .iter()
                .any(|l| t == *l || t.starts_with(&format!("{l}=")))
            {
                return true;
            }
            if let Some(c) = short {
                if t.starts_with('-') && !t.starts_with("--") && t.len() > 1 && t[1..].contains(c) {
                    return true;
                }
            }
        }
        false
    }
}

/// Lowercased basename, with a Windows `.exe` suffix removed. Case-folding
/// matters on case-insensitive filesystems, where `RM` runs `rm`.
pub fn program_name(text: &str) -> String {
    let base = text.rsplit(['/', '\\']).next().unwrap_or(text);
    let lower = base.to_ascii_lowercase();
    lower
        .strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(lower)
}

pub const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "ash",
    "fish",
    "tcsh",
    "csh",
    "yash",
    "busybox-sh",
];

pub fn is_shell(exe: &str) -> bool {
    SHELLS.contains(&exe)
}

pub fn is_interpreter(exe: &str) -> bool {
    is_python(exe)
        || matches!(
            exe,
            "perl"
                | "ruby"
                | "node"
                | "nodejs"
                | "php"
                | "deno"
                | "bun"
                | "lua"
                | "rscript"
                | "osascript"
                | "pwsh"
                | "powershell"
                | "awk"
                | "gawk"
                | "mawk"
                | "nawk"
                | "tclsh"
                | "irb"
        )
}

pub fn is_python(exe: &str) -> bool {
    exe == "python"
        || exe == "pypy"
        || exe == "pypy3"
        || exe
            .strip_prefix("python")
            .is_some_and(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// The result of analyzing a command line.
#[derive(Debug, Clone, Default)]
pub struct CommandSet {
    pub invocations: Vec<Invocation>,
    pub issues: Vec<Issue>,
    /// Reasons the command could not be fully resolved.
    pub unresolved: Vec<String>,
}

impl CommandSet {
    pub fn group(&self, group: usize) -> impl Iterator<Item = &Invocation> {
        self.invocations.iter().filter(move |i| i.group == group)
    }
}

/// Extract every invocation from a command line.
pub fn extract(command: &str, cwd: &Path, home: Option<&Path>) -> CommandSet {
    let mut extractor = Extractor {
        home: home.map(Path::to_path_buf),
        cwd: Some(cwd.to_path_buf()),
        vars: std::collections::HashMap::new(),
        next_group: 0,
        out: CommandSet::default(),
    };
    let script = shell::parse(command);
    extractor.script(&script, 0, Origin::Direct);
    extractor.out.issues.dedup();
    extractor.out
}

struct Extractor {
    home: Option<PathBuf>,
    cwd: Option<PathBuf>,
    /// Variables assigned static values earlier in the same command line
    /// (`F=.env; cat $F`).
    vars: std::collections::HashMap<String, String>,
    next_group: usize,
    out: CommandSet,
}

impl Extractor {
    fn nested(&mut self, text: &str, depth: usize, origin: Origin) {
        if depth > shell::MAX_DEPTH {
            self.out.issues.push(Issue::TooDeep);
            return;
        }
        let script = shell::parse_at_depth(text, depth);
        self.script(&script, depth, origin);
    }

    fn script(&mut self, script: &Script, depth: usize, origin: Origin) {
        self.out.issues.extend(script.issues.iter().cloned());
        for pipeline in &script.pipelines {
            let group = self.next_group;
            self.next_group += 1;
            let mut upstream_text: Option<String> = None;
            for (position, sc) in pipeline.commands.iter().enumerate() {
                let piped_text = if sc.stdin_piped {
                    upstream_text.take()
                } else {
                    None
                };
                let index = self.simple(sc, group, position, origin, depth, piped_text);
                upstream_text = index.and_then(|i| literal_output(&self.out.invocations[i]));
            }
        }
    }

    /// Returns the index of the main invocation, if any.
    fn simple(
        &mut self,
        sc: &SimpleCommand,
        group: usize,
        position: usize,
        origin: Origin,
        depth: usize,
        piped_text: Option<String>,
    ) -> Option<usize> {
        let mut nested: Vec<(String, Origin)> = Vec::new();
        if sc.words.is_empty() {
            for (name, value) in &sc.assignments {
                self.assign(name, value);
            }
        }
        let words: Vec<Word> = sc.words.iter().flat_map(|w| self.expand(w)).collect();
        let (argv, wrappers, dynamic_args) = self.unwrap(words, &mut nested);
        let exe = match argv.first() {
            Some(w) if w.is_static() => program_name(&w.text),
            _ => String::new(),
        };
        let mut inv = Invocation {
            argv,
            exe,
            wrappers,
            assignments: sc.assignments.clone(),
            redirects: sc.redirects.clone(),
            stdin_piped: sc.stdin_piped,
            group,
            position,
            origin,
            cwd: self.cwd.clone(),
            dynamic_args,
            executes: None,
        };
        self.classify_execution(&mut inv, piped_text, &mut nested);
        let find_execs = if inv.exe == "find" {
            find_exec_commands(&inv)
        } else {
            Vec::new()
        };
        self.track_cd(&inv);
        if matches!(
            inv.exe.as_str(),
            "export" | "declare" | "local" | "readonly" | "typeset"
        ) {
            for w in inv.args().to_vec() {
                if let Some((name, value)) = w.text.split_once('=') {
                    if !name.starts_with('-') {
                        let mut v = w.clone();
                        v.text = value.to_string();
                        v.tilde = value.starts_with('~');
                        self.assign(name, &v);
                    }
                }
            }
        }
        let index = self.out.invocations.len();
        self.out.invocations.push(inv);

        for words in find_execs {
            let mut inner_nested = Vec::new();
            let (argv, wrappers, _) = self.unwrap(words, &mut inner_nested);
            let exe = match argv.first() {
                Some(w) if w.is_static() => program_name(&w.text),
                _ => String::new(),
            };
            let mut inv = Invocation {
                argv,
                exe,
                wrappers,
                assignments: Vec::new(),
                redirects: Vec::new(),
                stdin_piped: false,
                group,
                position,
                origin: Origin::FindExec,
                cwd: self.cwd.clone(),
                dynamic_args: true,
                executes: None,
            };
            self.classify_execution(&mut inv, None, &mut inner_nested);
            self.out.invocations.push(inv);
            for (text, origin) in inner_nested {
                self.nested(&text, depth + 1, origin);
            }
        }
        for (text, origin) in nested {
            self.nested(&text, depth + 1, origin);
        }
        Some(index)
    }

    /// Record `NAME=value` when the value is static; forget it otherwise.
    fn assign(&mut self, name: &str, value: &Word) {
        let value = self.substitute(value);
        if value.is_static() {
            let text = if value.tilde {
                paths::resolve(&value.text, true, None, self.home.as_deref())
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or(value.text)
            } else {
                value.text
            };
            self.vars.insert(name.to_string(), text);
        } else {
            self.vars.remove(name);
        }
    }

    /// A command word after substitution. An unquoted expansion whose value
    /// contains whitespace becomes several words, as in the shell
    /// (`c="rm -rf x"; $c`). If `IFS` was changed, the split is unknown and
    /// the word stays dynamic.
    fn expand(&self, word: &Word) -> Vec<Word> {
        if word.split && self.vars.contains_key("IFS") {
            return vec![word.clone()];
        }
        let sub = self.substitute(word);
        if !sub.vars.is_empty() || !word.split || !sub.text.contains(char::is_whitespace) {
            return vec![sub];
        }
        sub.text
            .split_whitespace()
            .map(|t| Word {
                text: t.to_string(),
                tilde: false,
                ..sub.clone()
            })
            .collect()
    }

    /// Replace references to variables with known static values.
    fn substitute(&self, word: &Word) -> Word {
        if word.vars.is_empty()
            || word.substitution
            || word.brace
            || !word.vars.iter().all(|v| self.vars.contains_key(v))
        {
            return word.clone();
        }
        let mut names: Vec<&String> = word.vars.iter().collect();
        names.sort_by_key(|n| std::cmp::Reverse(n.len()));
        let mut text = word.text.clone();
        for name in names {
            let value = &self.vars[name];
            text = text
                .replace(&format!("${{{name}}}"), value)
                .replace(&format!("${name}"), value);
        }
        Word {
            text,
            vars: Vec::new(),
            ..word.clone()
        }
    }

    fn track_cd(&mut self, inv: &Invocation) {
        if !matches!(inv.exe.as_str(), "cd" | "pushd") {
            return;
        }
        let target = inv.positionals().into_iter().next();
        self.cwd = match target {
            None => self.home.clone(),
            Some(w) if w.is_static() && w.text == "-" => None,
            Some(w) => paths::resolve_word(w, self.cwd.as_deref(), self.home.as_deref()),
        };
    }

    /// Strip wrappers. Returns the effective argv, the wrapper names, and
    /// whether arguments are appended at runtime.
    fn unwrap(
        &self,
        mut argv: Vec<Word>,
        nested: &mut Vec<(String, Origin)>,
    ) -> (Vec<Word>, Vec<String>, bool) {
        let mut wrappers = Vec::new();
        let mut dynamic_args = false;
        for _ in 0..16 {
            let Some(first) = argv.first() else { break };
            if !first.is_static() {
                break;
            }
            let name = program_name(&first.text);
            let second = argv.get(1).map(|w| w.text.as_str()).unwrap_or("");
            let start = match name.as_str() {
                "sudo" => skip_options(
                    &argv,
                    1,
                    &[
                        "-u",
                        "-g",
                        "-C",
                        "-D",
                        "-h",
                        "-p",
                        "-r",
                        "-t",
                        "-U",
                        "-T",
                        "--user",
                        "--group",
                        "--close-from",
                        "--chdir",
                        "--host",
                        "--prompt",
                        "--role",
                        "--type",
                        "--other-user",
                        "--command-timeout",
                    ],
                ),
                "doas" => skip_options(&argv, 1, &["-u", "-C"]),
                "pkexec" | "run0" => skip_options(&argv, 1, &["--user", "-u"]),
                "env" => {
                    let mut i = 1;
                    while i < argv.len() {
                        let t = argv[i].text.as_str();
                        if t == "--" {
                            i += 1;
                            break;
                        }
                        if t == "-S" || t == "--split-string" {
                            if let Some(s) = argv.get(i + 1) {
                                nested.push((s.text.clone(), Origin::ShellString));
                            }
                            i += 2;
                            continue;
                        }
                        if let Some(s) = t
                            .strip_prefix("--split-string=")
                            .or_else(|| t.strip_prefix("-S").filter(|s| !s.is_empty()))
                        {
                            nested.push((s.to_string(), Origin::ShellString));
                            i += 1;
                            continue;
                        }
                        if matches!(t, "-u" | "--unset" | "-C" | "--chdir" | "-P") {
                            i += 2;
                            continue;
                        }
                        if t.starts_with('-') && t.len() > 1 {
                            i += 1;
                            continue;
                        }
                        if t.contains('=') && !t.starts_with('=') {
                            i += 1;
                            continue;
                        }
                        break;
                    }
                    i
                }
                "nice" => skip_options(&argv, 1, &["-n", "--adjustment"]),
                "nohup" | "setsid" | "unbuffer" | "chronic" | "builtin" | "command"
                | "catchsegv" => skip_options(&argv, 1, &[]),
                "time" => skip_options(&argv, 1, &["-f", "--format", "-o", "--output"]),
                "exec" => skip_options(&argv, 1, &["-a"]),
                "stdbuf" => skip_options(
                    &argv,
                    1,
                    &["-i", "-o", "-e", "--input", "--output", "--error"],
                ),
                "ionice" => skip_options(
                    &argv,
                    1,
                    &["-c", "-n", "-p", "-P", "-u", "--class", "--classdata"],
                ),
                "caffeinate" => skip_options(&argv, 1, &["-t", "-w"]),
                "timeout" | "gtimeout" => {
                    skip_options(&argv, 1, &["-s", "--signal", "-k", "--kill-after"]) + 1
                }
                "chrt" | "taskset" => skip_options(&argv, 1, &[]) + 1,
                "flock" => {
                    // `flock [opts] FILE CMD…` or `flock [opts] FILE -c 'CMD'`
                    let file = skip_options_capturing(
                        &argv,
                        1,
                        &["-w", "--timeout", "-E", "--conflict-exit-code"],
                        &["-c", "--command"],
                        nested,
                    );
                    if matches!(
                        argv.get(file + 1).map(|w| w.text.as_str()),
                        Some("-c" | "--command")
                    ) {
                        if let Some(s) = argv.get(file + 2) {
                            nested.push((s.text.clone(), Origin::ShellString));
                        }
                        break;
                    }
                    file + 1
                }
                "su" | "runuser" => {
                    // `su [-] [user] [-c cmd]`: the positional is a user name,
                    // the command (if any) is a shell string. `su` stays the
                    // program so privilege escalation is still visible.
                    skip_options_capturing(
                        &argv,
                        1,
                        &[
                            "-s",
                            "--shell",
                            "-g",
                            "--group",
                            "-G",
                            "--supp-group",
                            "-w",
                            "--whitelist-environment",
                        ],
                        &["-c", "--command", "--session-command"],
                        nested,
                    );
                    for pair in argv.windows(2) {
                        if matches!(pair[0].text.as_str(), "-c" | "--command")
                            && !nested.iter().any(|(t, _)| *t == pair[1].text)
                        {
                            nested.push((pair[1].text.clone(), Origin::ShellString));
                        }
                    }
                    break;
                }
                "watch" => {
                    // watch joins its arguments and runs them with `sh -c`.
                    let i = skip_options(&argv, 1, &["-n", "--interval", "-d", "-q", "--equexit"]);
                    let rest: Vec<String> = argv[i.min(argv.len())..]
                        .iter()
                        .map(|w| w.text.clone())
                        .collect();
                    if !rest.is_empty() {
                        nested.push((rest.join(" "), Origin::ShellString));
                    }
                    break;
                }
                "xargs" => {
                    dynamic_args = true;
                    let i = skip_options(
                        &argv,
                        1,
                        &[
                            "-I",
                            "-L",
                            "-n",
                            "-P",
                            "-s",
                            "-d",
                            "-E",
                            "-a",
                            "--arg-file",
                            "--delimiter",
                            "--max-args",
                            "--max-procs",
                            "--max-lines",
                            "--replace",
                            "--eof",
                            "--process-slot-var",
                        ],
                    );
                    if i >= argv.len() {
                        // `xargs` alone runs `echo`.
                        wrappers.push(name);
                        argv = vec![Word::literal("echo")];
                        break;
                    }
                    i
                }
                "busybox" => 1,
                "uv" | "poetry" | "pipenv" | "pdm" | "rye" | "hatch" if second == "run" => {
                    skip_options(
                        &argv,
                        2,
                        &[
                            "--with",
                            "--with-requirements",
                            "--python",
                            "-p",
                            "--project",
                            "--directory",
                            "--env-file",
                            "--extra",
                            "--group",
                            "--package",
                            "--index",
                            "--index-url",
                            "-w",
                            "-e",
                            "--env",
                        ],
                    )
                }
                "bundle" | "asdf" if second == "exec" => skip_options(&argv, 2, &[]),
                "mise" | "rtx" if matches!(second, "exec" | "x") => {
                    // `mise exec node@20 -- node app.js`
                    match argv.iter().position(|w| w.text == "--") {
                        Some(i) => i + 1,
                        None => break,
                    }
                }
                "direnv" if second == "exec" => 3,
                _ => break,
            };
            if start >= argv.len() {
                // Nothing to wrap (`env`, `sudo -v`): the wrapper is the program.
                break;
            }
            wrappers.push(name);
            argv.drain(..start);
        }
        (argv, wrappers, dynamic_args)
    }

    fn classify_execution(
        &mut self,
        inv: &mut Invocation,
        piped_text: Option<String>,
        nested: &mut Vec<(String, Origin)>,
    ) {
        let exe = inv.exe.clone();
        if is_shell(&exe) {
            let mut has_c = false;
            let mut reads_stdin_flag = false;
            let mut script: Option<Word> = None;
            let mut i = 1;
            while i < inv.argv.len() {
                let w = &inv.argv[i];
                let t = w.text.as_str();
                if t == "--" || t == "-" {
                    i += 1;
                    if t == "-" {
                        reads_stdin_flag = true;
                    }
                    break;
                }
                if matches!(t, "--rcfile" | "--init-file" | "-o" | "+o" | "-O" | "+O") {
                    i += 2;
                    continue;
                }
                if t.starts_with("--") {
                    i += 1;
                    continue;
                }
                if (t.starts_with('-') || t.starts_with('+')) && t.len() > 1 && w.is_static() {
                    has_c |= t[1..].contains('c');
                    reads_stdin_flag |= t[1..].contains('s');
                    i += 1;
                    continue;
                }
                break;
            }
            if let Some(w) = inv.argv.get(i) {
                script = Some(w.clone());
            }
            if has_c {
                if let Some(w) = script {
                    if w.is_static() {
                        nested.push((w.text.clone(), Origin::ShellString));
                    } else {
                        self.out
                            .unresolved
                            .push(format!("`{exe} -c` runs a dynamically built command"));
                    }
                    inv.executes = Some(Executes::ShellString(w));
                    return;
                }
            }
            if let Some(w) = script.filter(|_| !reads_stdin_flag) {
                inv.executes = Some(Executes::ScriptFile(w));
                return;
            }
            inv.executes = Some(Executes::Stdin {
                resolved: self.stdin_script(inv, piped_text, nested),
            });
            return;
        }
        if exe == "eval" {
            let args = inv.args();
            let resolved = args.iter().all(Word::is_static);
            if resolved {
                let text = args
                    .iter()
                    .map(|w| w.text.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                nested.push((text, Origin::Eval));
            } else {
                self.out
                    .unresolved
                    .push("`eval` of a dynamically built command".into());
            }
            inv.executes = Some(Executes::Eval { resolved });
            return;
        }
        if exe == "source" || exe == "." {
            if let Some(w) = inv.args().first() {
                inv.executes = Some(Executes::ScriptFile(w.clone()));
            }
            return;
        }
        if exe == "git" {
            for pair in inv.args().windows(2) {
                if pair[0].text == "-c" {
                    if let Some((key, value)) = pair[1].text.split_once('=') {
                        if key.to_ascii_lowercase().starts_with("alias.") {
                            if let Some(cmd) = value.strip_prefix('!') {
                                nested.push((cmd.to_string(), Origin::GitAlias));
                            }
                        }
                    }
                }
            }
            return;
        }
        if exe == "ssh" {
            // argv[host] then the remote command, which ssh joins with spaces.
            let host = skip_options(
                &inv.argv,
                1,
                &[
                    "-p", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-W", "-b", "-c", "-E",
                    "-e", "-m", "-O", "-Q", "-S", "-w", "-B",
                ],
            );
            if host + 1 < inv.argv.len() {
                let remote: Vec<&str> = inv.argv[host + 1..]
                    .iter()
                    .map(|w| w.text.as_str())
                    .collect();
                nested.push((remote.join(" "), Origin::Remote));
            }
            return;
        }
        if is_interpreter(&exe) {
            if let Some(code) = inline_code(inv).or_else(|| stdin_program(inv)) {
                for command in embedded_shell_commands(&code) {
                    nested.push((command, Origin::InlineCode));
                }
                inv.executes = Some(Executes::InlineCode {
                    interpreter: exe.clone(),
                    code,
                });
                return;
            }
            if exe.contains("awk") {
                return;
            }
            let positional = inv
                .args()
                .iter()
                .find(|w| !w.text.starts_with('-') || w.text == "-")
                .cloned();
            let module_mode = is_python(&exe) && inv.has_flag(None, &["-m"]);
            match positional {
                Some(w) if w.text != "-" && !module_mode => {
                    inv.executes = Some(Executes::ScriptFile(w));
                }
                _ if module_mode || inv.has_flag(None, &["--version", "-V", "--help", "-h"]) => {}
                positional => {
                    let heredoc = inv.redirects.iter().any(|r| {
                        matches!(r.kind, RedirectKind::Heredoc | RedirectKind::HereString)
                    });
                    if positional.is_some() || inv.stdin_piped || heredoc {
                        inv.executes = Some(Executes::Stdin { resolved: false });
                    }
                }
            }
        }
    }

    /// Queue the script a shell reads from stdin for analysis. Returns true
    /// when its content is statically known.
    fn stdin_script(
        &self,
        inv: &Invocation,
        piped_text: Option<String>,
        nested: &mut Vec<(String, Origin)>,
    ) -> bool {
        for r in &inv.redirects {
            match r.kind {
                RedirectKind::Heredoc => {
                    if let Some(body) = &r.body {
                        nested.push((body.clone(), Origin::Stdin));
                        return true;
                    }
                }
                RedirectKind::HereString => {
                    if r.target.is_static() {
                        nested.push((r.target.text.clone(), Origin::Stdin));
                        return true;
                    }
                    return false;
                }
                RedirectKind::Read => return false,
                _ => {}
            }
        }
        if inv.stdin_piped {
            if let Some(text) = piped_text {
                nested.push((text, Origin::Stdin));
                return true;
            }
            return false;
        }
        // Interactive shell or stdin from the caller: nothing to resolve here.
        true
    }
}

/// Skip options; `with_arg` options consume the next word. Handles short
/// clusters (`-Eu root`) and attached values (`-uroot`, `--user=root`).
fn skip_options(argv: &[Word], start: usize, with_arg: &[&str]) -> usize {
    skip_options_capturing(argv, start, with_arg, &[], &mut Vec::new())
}

fn skip_options_capturing(
    argv: &[Word],
    start: usize,
    with_arg: &[&str],
    shell_string: &[&str],
    nested: &mut Vec<(String, Origin)>,
) -> usize {
    let mut i = start;
    while i < argv.len() {
        let t = argv[i].text.as_str();
        if t == "--" {
            return i + 1;
        }
        if !t.starts_with('-') || t == "-" {
            return i;
        }
        if let Some((opt, value)) = t.split_once('=') {
            if shell_string.contains(&opt) {
                nested.push((value.to_string(), Origin::ShellString));
            }
            i += 1;
            continue;
        }
        if shell_string.contains(&t) {
            if let Some(s) = argv.get(i + 1) {
                nested.push((s.text.clone(), Origin::ShellString));
            }
            i += 2;
            continue;
        }
        if with_arg.contains(&t) {
            i += 2;
            continue;
        }
        if !t.starts_with("--") && t.len() > 2 {
            // Short cluster: the first option letter that takes an argument
            // consumes the rest of the cluster, or the next word.
            let letters: Vec<char> = t[1..].chars().collect();
            let mut consumed_next = false;
            for (k, c) in letters.iter().enumerate() {
                let flag = format!("-{c}");
                if shell_string.contains(&flag.as_str()) || with_arg.contains(&flag.as_str()) {
                    let attached: String = letters[k + 1..].iter().collect();
                    let value = if attached.is_empty() {
                        consumed_next = true;
                        argv.get(i + 1).map(|w| w.text.clone())
                    } else {
                        Some(attached)
                    };
                    if shell_string.contains(&flag.as_str()) {
                        if let Some(v) = value {
                            nested.push((v, Origin::ShellString));
                        }
                    }
                    break;
                }
            }
            i += if consumed_next { 2 } else { 1 };
            continue;
        }
        i += 1;
    }
    i
}

/// Text an `echo`/`printf` with static arguments writes to stdout.
fn literal_output(inv: &Invocation) -> Option<String> {
    let args = inv.args();
    if !args.iter().all(Word::is_static) {
        return None;
    }
    match inv.exe.as_str() {
        "echo" => {
            let words: Vec<&str> = args
                .iter()
                .map(|w| w.text.as_str())
                .skip_while(|t| matches!(*t, "-n" | "-e" | "-E" | "-ne" | "-en"))
                .collect();
            Some(words.join(" "))
        }
        "printf" => {
            let (format, rest) = args.split_first()?;
            let mut out = format.text.replace("\\n", "\n").replace("\\t", "\t");
            for arg in rest {
                if let Some(pos) = out.find("%s") {
                    out.replace_range(pos..pos + 2, &arg.text);
                }
            }
            Some(out)
        }
        _ => None,
    }
}

/// The argv of each `-exec`/`-execdir`/`-ok` clause in a `find` command.
fn find_exec_commands(inv: &Invocation) -> Vec<Vec<Word>> {
    let mut out = Vec::new();
    let args = inv.args();
    let mut i = 0;
    while i < args.len() {
        if matches!(
            args[i].text.as_str(),
            "-exec" | "-execdir" | "-ok" | "-okdir"
        ) {
            let mut words = Vec::new();
            i += 1;
            while i < args.len() && !matches!(args[i].text.as_str(), ";" | "+") {
                words.push(args[i].clone());
                i += 1;
            }
            if !words.is_empty() {
                out.push(words);
            }
        }
        i += 1;
    }
    out
}

/// Program text an interpreter reads from a heredoc or here-string
/// (`python3 - <<EOF … EOF`).
fn stdin_program(inv: &Invocation) -> Option<String> {
    if inv.exe.contains("awk") {
        return None;
    }
    let script = inv
        .args()
        .iter()
        .find(|w| !w.text.starts_with('-') || w.text == "-");
    if script.is_some_and(|w| w.text != "-") {
        return None;
    }
    inv.redirects.iter().find_map(|r| match r.kind {
        RedirectKind::Heredoc => r.body.clone(),
        RedirectKind::HereString if r.target.is_static() => Some(r.target.text.clone()),
        _ => None,
    })
}

/// Inline program text: `python -c CODE`, `node -e CODE`, `awk PROGRAM`, …
pub fn inline_code(inv: &Invocation) -> Option<String> {
    let exe = inv.exe.as_str();
    let flags: &[&str] = if is_python(exe) {
        &["-c"]
    } else {
        match exe {
            "perl" => &["-e", "-E"],
            "ruby" => &["-e"],
            "node" | "nodejs" | "bun" => &["-e", "--eval", "-p", "--print"],
            "php" => &["-r"],
            "lua" | "rscript" | "osascript" => &["-e"],
            "pwsh" | "powershell" => &["-c", "-command", "-encodedcommand", "-e", "-ec"],
            "deno" => &["eval"],
            "tclsh" => &[],
            e if e.contains("awk") => {
                // The first non-option argument is the program.
                let mut skip_next = false;
                for w in inv.args() {
                    if skip_next {
                        skip_next = false;
                        continue;
                    }
                    if matches!(w.text.as_str(), "-f" | "-F" | "-v" | "--file") {
                        if w.text == "-f" || w.text == "--file" {
                            return None;
                        }
                        skip_next = true;
                        continue;
                    }
                    if w.text.starts_with('-') {
                        continue;
                    }
                    return Some(w.text.clone());
                }
                return None;
            }
            _ => return None,
        }
    };
    let args = inv.args();
    for (i, w) in args.iter().enumerate() {
        let t = w.text.to_ascii_lowercase();
        if flags.contains(&t.as_str()) {
            let mut code = args.get(i + 1)?.text.clone();
            // `perl -e CODE -e MORE`
            for extra in args[i + 2..].windows(2) {
                if flags.contains(&extra[0].text.as_str()) {
                    code.push('\n');
                    code.push_str(&extra[1].text);
                }
            }
            return Some(code);
        }
        // Attached form: `-c'code'` is rare but `-e'…'` exists in perl.
        if let Some(rest) = flags.iter().find_map(|f| {
            w.text
                .strip_prefix(f)
                .filter(|r| !r.is_empty() && f.len() == 2)
        }) {
            if exe == "perl" || exe == "ruby" {
                return Some(rest.to_string());
            }
        }
    }
    None
}

/// Shell commands passed as string literals to `system`-style calls inside
/// inline code: `os.system("…")`, `subprocess.run("…", shell=True)`,
/// `execSync('…')`, `` `…` `` in Ruby/Perl, `do shell script "…"`.
fn embedded_shell_commands(code: &str) -> Vec<String> {
    static CALLS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?:\bsystem|\bpopen|\bexecSync|\bexec|\bspawnSync|\bcheck_output|\bcheck_call|\bgetoutput|\bgetstatusoutput|\bcall|\brun|\bPopen|\bshell_exec|\bpassthru|\bdo shell script)\s*\(?\s*(?:[rbuf]?)(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')"#)
            .expect("valid regex")
    });
    static BACKTICKS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"`([^`]+)`").expect("valid regex"));
    let mut out = Vec::new();
    for caps in CALLS.captures_iter(code) {
        if let Some(m) = caps.get(1).or_else(|| caps.get(2)) {
            out.push(m.as_str().replace("\\\"", "\"").replace("\\'", "'"));
        }
    }
    for caps in BACKTICKS.captures_iter(code) {
        out.push(caps[1].to_string());
    }
    out
}

#[cfg(test)]
mod tests;
