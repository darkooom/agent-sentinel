use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;

use super::{option_value, Out, Scope};
use crate::command::{Executes, Invocation};
use crate::{Finding, Risk};

pub(crate) const DOWNLOADERS: &[&str] = &[
    "curl",
    "wget",
    "fetch",
    "http",
    "https",
    "xh",
    "xhs",
    "aria2c",
    "lwp-request",
    "lwp-download",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
];

pub(crate) fn is_downloader(exe: &str) -> bool {
    DOWNLOADERS.contains(&exe)
}

fn is_decoder(inv: &Invocation) -> bool {
    match inv.exe.as_str() {
        "base64" | "base32" | "gbase64" => {
            inv.has_flag(Some('d'), &["--decode"]) || inv.has_flag(Some('D'), &[])
        }
        "xxd" => inv.has_flag(Some('r'), &["-revert"]),
        "openssl" => inv
            .args()
            .iter()
            .any(|w| w.text == "-d" || w.text == "base64" || w.text == "enc"),
        "gunzip" | "zcat" | "bzcat" | "xzcat" | "uudecode" | "rev" => true,
        "gzip" | "bzip2" | "xz" => inv.has_flag(Some('d'), &["--decompress"]),
        _ => false,
    }
}

pub(crate) fn detect(scope: &Scope, out: &mut Out) {
    let set = scope.set;

    let mut unparsed: Vec<String> = set.issues.iter().map(|i| i.describe()).collect();
    unparsed.dedup();
    if let Some(first) = unparsed.first() {
        out.push(
            Finding::new(
                "exec.obfuscated",
                Risk::High,
                format!("Command could not be fully analyzed: {first}"),
            )
            .with_details(unparsed.iter().skip(1).cloned().collect()),
        );
    }
    for reason in &set.unresolved {
        out.push(Finding::new(
            "exec.obfuscated",
            Risk::High,
            format!("Command could not be fully analyzed: {reason}"),
        ));
    }

    let downloads: Vec<&Invocation> = set
        .invocations
        .iter()
        .filter(|i| is_downloader(&i.exe))
        .collect();
    let downloaded = downloaded_files(scope, &downloads);

    for inv in &set.invocations {
        if inv.exe_dynamic() {
            let text = &inv.argv[0].text;
            out.push(Finding::new(
                "exec.obfuscated",
                Risk::High,
                format!("Program name is computed at runtime: `{text}`"),
            ));
        }

        match &inv.executes {
            Some(Executes::Stdin { resolved: false }) => {
                if inv.stdin_piped {
                    let upstream: Vec<&Invocation> = set
                        .group(inv.group)
                        .filter(|i| i.position < inv.position)
                        .collect();
                    if upstream.iter().any(|i| is_downloader(&i.exe))
                        || (upstream.is_empty() && !downloads.is_empty())
                    {
                        out.push(Finding::new(
                            "exec.remote-script",
                            Risk::Critical,
                            format!("Pipes downloaded content into {}", inv.exe),
                        ));
                    } else if upstream.iter().any(|i| is_decoder(i)) {
                        out.push(Finding::new(
                            "exec.obfuscated",
                            Risk::Critical,
                            format!("Decodes data and pipes it into {}", inv.exe),
                        ));
                    } else {
                        out.push(Finding::new(
                            "exec.pipe-to-shell",
                            Risk::High,
                            format!("Pipes data into {}", inv.exe),
                        ));
                    }
                } else {
                    for (text, path) in scope.redirect_reads(inv) {
                        if is_downloaded(&downloaded, &text, path.as_ref()) {
                            out.push(Finding::new(
                                "exec.remote-script",
                                Risk::Critical,
                                format!("Downloads {text} and runs it with {}", inv.exe),
                            ));
                        }
                    }
                }
            }
            Some(Executes::ShellString(word)) if word.substitution && !downloads.is_empty() => {
                out.push(Finding::new(
                    "exec.remote-script",
                    Risk::Critical,
                    format!("Runs the output of a download with {} -c", inv.exe),
                ));
            }
            Some(Executes::ScriptFile(word)) => {
                if word.substitution && !downloads.is_empty() {
                    out.push(Finding::new(
                        "exec.remote-script",
                        Risk::Critical,
                        format!("Runs a downloaded script with {}", inv.exe),
                    ));
                } else if word.is_static()
                    && is_downloaded(&downloaded, &word.text, scope.resolve(inv, word).as_ref())
                {
                    out.push(Finding::new(
                        "exec.remote-script",
                        Risk::Critical,
                        format!("Downloads {} and executes it", word.text),
                    ));
                }
            }
            Some(Executes::Eval { resolved: false }) => {
                if inv.args().iter().any(|w| w.substitution) && !downloads.is_empty() {
                    out.push(Finding::new(
                        "exec.remote-script",
                        Risk::Critical,
                        "Evaluates the output of a download",
                    ));
                }
            }
            Some(Executes::InlineCode { interpreter, code }) => inline(interpreter, code, inv, out),
            _ => {}
        }

        // `./install.sh` after downloading install.sh
        if let Some(first) = inv.argv.first() {
            if first.is_static()
                && first.text.contains('/')
                && is_downloaded(&downloaded, &first.text, scope.resolve(inv, first).as_ref())
            {
                out.push(Finding::new(
                    "exec.remote-script",
                    Risk::Critical,
                    format!("Downloads {} and executes it", first.text),
                ));
            }
        }

        privilege(inv, out);
        system(inv, out);
    }

    if let Some(command) = &scope.action.command {
        if is_fork_bomb(command) {
            out.push(Finding::new(
                "exec.fork-bomb",
                Risk::Critical,
                "Fork bomb: spawns processes until the machine is unusable",
            ));
        }
    }
}

struct Downloaded {
    names: Vec<String>,
    paths: Vec<PathBuf>,
}

fn downloaded_files(scope: &Scope, downloads: &[&Invocation]) -> Downloaded {
    let mut names = Vec::new();
    let mut paths = Vec::new();
    for inv in downloads {
        let mut files: Vec<String> = Vec::new();
        if let Some(f) = option_value(inv, &["-o", "--output", "--output-document"]) {
            files.push(f);
        }
        if inv.exe == "wget" {
            if let Some(f) = option_value(inv, &["-O"]) {
                files.push(f);
            }
        }
        let remote_name = inv.exe == "wget" && files.is_empty()
            || inv.has_flag(None, &["-O", "--remote-name", "--remote-name-all"]);
        if remote_name {
            for w in inv.args() {
                if let Some(name) = w
                    .text
                    .split("://")
                    .nth(1)
                    .and_then(|rest| rest.split('?').next())
                    .and_then(|p| p.rsplit('/').next())
                {
                    if !name.is_empty() && !name.contains(':') {
                        files.push(name.to_string());
                    }
                }
            }
        }
        for (text, _) in scope.redirect_writes(inv) {
            files.push(text);
        }
        for f in files {
            if let Some(p) = scope.resolve_text(inv, &f) {
                paths.push(p);
            }
            names.push(f.rsplit('/').next().unwrap_or(&f).to_string());
        }
    }
    Downloaded { names, paths }
}

fn is_downloaded(d: &Downloaded, text: &str, path: Option<&PathBuf>) -> bool {
    if path.is_some_and(|p| d.paths.contains(p)) {
        return true;
    }
    let base = text.rsplit('/').next().unwrap_or(text);
    !base.is_empty() && d.names.iter().any(|n| n == base)
}

fn inline(interpreter: &str, code: &str, inv: &Invocation, out: &mut Out) {
    static DECODE_EXEC: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(?:\bexec|\beval|\bFunction|\bsystem|\bcompile)\s*\(.*(?:b64decode|atob|base64|fromCharCode|unhexlify|decode\(|\\x[0-9a-f]{2}.*\\x[0-9a-f]{2})")
            .expect("valid regex")
    });
    if matches!(interpreter, "pwsh" | "powershell")
        && inv.args().iter().any(|w| {
            matches!(
                w.text.to_ascii_lowercase().as_str(),
                "-encodedcommand" | "-enc" | "-e" | "-ec"
            )
        })
    {
        out.push(Finding::new(
            "exec.obfuscated",
            Risk::Critical,
            "PowerShell -EncodedCommand hides the script being run",
        ));
        return;
    }
    if DECODE_EXEC.is_match(code) {
        out.push(Finding::new(
            "exec.obfuscated",
            Risk::Critical,
            format!("Inline {interpreter} code decodes and executes a payload"),
        ));
        return;
    }
    if !interpreter.contains("awk") {
        out.push(Finding::new(
            "exec.inline-code",
            Risk::Medium,
            format!("Runs inline {interpreter} code"),
        ));
    }
}

fn privilege(inv: &Invocation, out: &mut Out) {
    const ESCALATE: &[&str] = &["sudo", "doas", "pkexec", "run0", "su", "runuser"];
    let via = inv
        .wrappers
        .iter()
        .find(|w| ESCALATE.contains(&w.as_str()))
        .cloned()
        .or_else(|| {
            ESCALATE
                .contains(&inv.exe.as_str())
                .then(|| inv.exe.clone())
        });
    if let Some(via) = via {
        if !(via == "sudo" && inv.exe == "sudo" && inv.has_flag(Some('k'), &["--reset-timestamp"]))
        {
            out.push(Finding::new(
                "exec.privilege",
                Risk::High,
                format!("Runs with elevated privileges via {via}"),
            ));
        }
    }
    if matches!(inv.exe.as_str(), "docker" | "podman" | "nerdctl") {
        let args: Vec<&str> = inv.args().iter().map(|w| w.text.as_str()).collect();
        if args
            .iter()
            .any(|a| *a == "--privileged" || *a == "--pid=host")
        {
            out.push(Finding::new(
                "exec.privilege",
                Risk::High,
                "Starts a privileged container (full access to the host)",
            ));
        }
        if args.windows(2).any(|w| {
            matches!(w[0], "-v" | "--volume")
                && (w[1].starts_with("/:") || w[1].starts_with("/var/run/docker.sock"))
        }) {
            out.push(Finding::new(
                "exec.privilege",
                Risk::High,
                "Mounts the host root or Docker socket into a container",
            ));
        }
    }
}

fn system(inv: &Invocation, out: &mut Out) {
    let pos: Vec<String> = inv
        .positionals()
        .iter()
        .map(|w| w.text.to_ascii_lowercase())
        .collect();
    let first = pos.first().map(String::as_str).unwrap_or("");
    let msg = match inv.exe.as_str() {
        "shutdown" | "reboot" | "halt" | "poweroff" => {
            Some((Risk::High, "Shuts down or reboots the machine".to_string()))
        }
        "init" | "telinit" if matches!(first, "0" | "6") => {
            Some((Risk::High, "Shuts down or reboots the machine".to_string()))
        }
        "systemctl" => match first {
            "poweroff" | "reboot" | "halt" | "kexec" | "suspend" | "hibernate" => {
                Some((Risk::High, format!("systemctl {first} the machine")))
            }
            "stop" | "disable" | "mask" | "kill" => Some((
                Risk::Medium,
                format!("systemctl {first} stops system services"),
            )),
            "enable" => Some((
                Risk::Medium,
                "Enables a service to start automatically (persistence)".to_string(),
            )),
            _ => None,
        },
        "kill" if inv.args().iter().any(|w| w.text == "-1") => {
            Some((Risk::High, "Kills every process you own".to_string()))
        }
        "killall" | "pkill" => Some((Risk::Medium, format!("{} kills processes by name", inv.exe))),
        "launchctl" if matches!(first, "unload" | "bootout" | "remove" | "disable") => Some((
            Risk::Medium,
            format!("launchctl {first} stops system services"),
        )),
        "launchctl" if matches!(first, "load" | "bootstrap" | "enable") => Some((
            Risk::Medium,
            "Registers a launch agent (persistence)".to_string(),
        )),
        "crontab" if inv.has_flag(Some('r'), &[]) => Some((
            Risk::High,
            "crontab -r deletes all scheduled jobs".to_string(),
        )),
        "crontab" if !inv.has_flag(Some('l'), &[]) => Some((
            Risk::Medium,
            "Installs scheduled jobs (persistence)".to_string(),
        )),
        "csrutil" if first == "disable" => Some((
            Risk::Critical,
            "Disables macOS System Integrity Protection".to_string(),
        )),
        "spctl" if inv.has_flag(None, &["--master-disable", "--global-disable"]) => {
            Some((Risk::Critical, "Disables macOS Gatekeeper".to_string()))
        }
        "setenforce" if first == "0" => {
            Some((Risk::High, "Disables SELinux enforcement".to_string()))
        }
        "ufw" if first == "disable" => Some((Risk::High, "Disables the firewall".to_string())),
        "iptables" | "ip6tables" if inv.has_flag(Some('F'), &["--flush"]) => {
            Some((Risk::High, "Flushes all firewall rules".to_string()))
        }
        "pfctl" if inv.args().iter().any(|w| w.text == "-d") => Some((
            Risk::High,
            "Disables the packet filter firewall".to_string(),
        )),
        "nft" if pos.windows(2).any(|w| w[0] == "flush" && w[1] == "ruleset") => {
            Some((Risk::High, "Flushes all firewall rules".to_string()))
        }
        "history" if inv.has_flag(Some('c'), &[]) => {
            Some((Risk::Medium, "Clears shell history".to_string()))
        }
        "chsh" | "passwd" | "useradd" | "userdel" | "usermod" | "groupadd" | "visudo"
        | "adduser" | "deluser" | "dscl" | "sysadminctl" => Some((
            Risk::High,
            format!("{} modifies user accounts or privileges", inv.exe),
        )),
        "xattr"
            if inv
                .args()
                .iter()
                .any(|w| w.text.contains("com.apple.quarantine"))
                || inv.has_flag(Some('c'), &[]) =>
        {
            Some((
                Risk::Medium,
                "Removes the quarantine flag (skips Gatekeeper checks)".to_string(),
            ))
        }
        _ => None,
    };
    if let Some((risk, message)) = msg {
        out.push(Finding::new("exec.system", risk, message));
    }
}

fn is_fork_bomb(command: &str) -> bool {
    static BOMB: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"([A-Za-z_:.][\w:.]*)\s*\(\s*\)\s*\{\s*([A-Za-z_:.][\w:.]*)\s*\|\s*([A-Za-z_:.][\w:.]*)\s*&\s*;?\s*\}").expect("valid regex")
    });
    BOMB.captures_iter(command)
        .any(|c| c[1] == c[2] && c[2] == c[3])
}
