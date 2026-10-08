use std::sync::LazyLock;

use regex::Regex;

use super::exec::is_downloader;
use super::{option_value, Out, Scope};
use crate::command::{Executes, Invocation};
use crate::{Finding, Host, Risk};

/// Options of curl/wget/httpie that take a separate value, so the value is
/// not mistaken for a host.
const VALUE_OPTIONS: &[&str] = &[
    "-o",
    "--output",
    "-d",
    "--data",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--json",
    "-H",
    "--header",
    "-X",
    "--request",
    "-u",
    "--user",
    "-A",
    "--user-agent",
    "-e",
    "--referer",
    "-b",
    "--cookie",
    "-c",
    "--cookie-jar",
    "-F",
    "--form",
    "-T",
    "--upload-file",
    "-K",
    "--config",
    "-w",
    "--write-out",
    "-x",
    "--proxy",
    "-m",
    "--max-time",
    "-r",
    "--range",
    "-E",
    "--cert",
    "--key",
    "--cacert",
    "--connect-timeout",
    "--retry",
    "--resolve",
    "-C",
    "--continue-at",
    "--output-dir",
    "-O",
    "--output-document",
    "-P",
    "--directory-prefix",
    "--post-data",
    "--post-file",
    "--body-file",
    "--header-file",
    "-t",
    "--tries",
    "-T",
    "--timeout",
    "-U",
    "--limit-rate",
    "--interface",
    "--dns-servers",
    "--oauth2-bearer",
    "-Y",
    "-y",
    "-z",
];

pub(crate) fn detect(scope: &Scope, out: &mut Out) {
    let mut hosts: Vec<Host> = Vec::new();
    for inv in &scope.set.invocations {
        let found = hosts_of(inv);
        uploads(scope, inv, &found, out);
        listeners(inv, out);
        hosts.extend(found);
    }
    for host in hosts {
        add_host(host, out);
    }
}

pub(crate) fn add_host(host: Host, out: &mut Out) {
    if is_loopback(&host.name) {
        return;
    }
    if !out.facts.hosts.iter().any(|h| h.name == host.name) {
        out.push(Finding::new(
            "net.request",
            Risk::Medium,
            format!("Connects to {}", host.name),
        ));
        out.facts.hosts.push(host);
    }
}

fn is_loopback(host: &str) -> bool {
    matches!(
        host,
        "localhost" | "127.0.0.1" | "::1" | "[::1]" | "0.0.0.0"
    ) || host.ends_with(".localhost")
        || host.starts_with("127.")
}

fn hosts_of(inv: &Invocation) -> Vec<Host> {
    let mut out = Vec::new();
    let exe = inv.exe.as_str();
    let args = inv.args();
    if is_downloader(exe) {
        let mut skip = false;
        for w in args {
            let t = w.text.as_str();
            if skip {
                skip = false;
                continue;
            }
            if VALUE_OPTIONS.contains(&t) {
                skip = t != "-O" || exe == "wget";
                continue;
            }
            if let Some(v) = t.strip_prefix("--url=") {
                out.extend(parse_host(v));
                continue;
            }
            if t.starts_with('-') {
                continue;
            }
            // httpie: `http POST example.com key=value`
            if matches!(exe, "http" | "https" | "xh" | "xhs")
                && (t.chars().all(|c| c.is_ascii_uppercase())
                    || t.contains('=') && !t.contains("://"))
            {
                continue;
            }
            out.extend(parse_host(t));
        }
    } else if exe == "git" {
        let network_sub = args.iter().any(|w| {
            matches!(
                w.text.as_str(),
                "clone" | "fetch" | "pull" | "push" | "ls-remote" | "remote" | "submodule"
            )
        });
        if network_sub {
            for w in args {
                out.extend(parse_git_url(&w.text));
            }
        }
    } else if matches!(exe, "ssh" | "mosh" | "sftp" | "ftp" | "telnet") {
        let skip_opts = [
            "-p", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-W", "-b", "-c", "-E", "-e",
            "-m", "-O", "-Q", "-S", "-w", "-B", "-P",
        ];
        let mut i = 0;
        let mut target = None;
        while i < args.len() {
            let t = args[i].text.as_str();
            if skip_opts.contains(&t) {
                i += 2;
                continue;
            }
            if t.starts_with('-') {
                i += 1;
                continue;
            }
            target = Some(t);
            break;
        }
        if let Some(t) = target {
            let host = t.rsplit('@').next().unwrap_or(t);
            out.extend(parse_host(&format!("{exe}://{host}")));
        }
    } else if matches!(exe, "scp" | "rsync" | "rclone") {
        for w in args {
            let t = w.text.as_str();
            if t.starts_with('-') {
                continue;
            }
            if t.contains("://") {
                out.extend(parse_host(t));
            } else if let Some((host, _)) = t.split_once(':') {
                if !host.is_empty() && !host.contains('/') && host.len() > 1 {
                    let host = host.rsplit('@').next().unwrap_or(host);
                    out.extend(parse_host(&format!("ssh://{host}")));
                }
            }
        }
    } else if matches!(exe, "nc" | "ncat" | "netcat") && !inv.has_flag(Some('l'), &["--listen"]) {
        let pos: Vec<&str> = inv.positionals().iter().map(|w| w.text.as_str()).collect();
        if let Some(host) = pos.first() {
            let port = pos.get(1).and_then(|p| p.parse().ok());
            out.extend(parse_host(host).map(|mut h| {
                h.port = port;
                h.scheme = Some("tcp".into());
                h
            }));
        }
    } else if let Some(Executes::InlineCode { code, .. }) = &inv.executes {
        static URL: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"(?i)\b(?:https?|wss?|ftp)://[^\s'\x22`)]+").expect("valid regex")
        });
        for m in URL.find_iter(code) {
            out.extend(parse_host(m.as_str()));
        }
    } else if is_package_manager(exe) {
        for w in args {
            if w.text.contains("://") {
                out.extend(parse_host(w.text.trim_start_matches("git+")));
            }
        }
    }
    out
}

fn is_package_manager(exe: &str) -> bool {
    matches!(
        exe,
        "npm"
            | "pnpm"
            | "yarn"
            | "bun"
            | "pip"
            | "pip3"
            | "uv"
            | "pipx"
            | "cargo"
            | "go"
            | "gem"
            | "deno"
            | "composer"
            | "poetry"
    )
}

/// Extract the host from a URL or `host[:port][/path]`.
pub(crate) fn parse_host(text: &str) -> Option<Host> {
    static HOSTLIKE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$|^\d{1,3}(?:\.\d{1,3}){3}$|^localhost$|^\[[0-9a-fA-F:]+\]$").expect("valid regex")
    });
    let (scheme, rest) = match text.split_once("://") {
        Some((s, r)) => (Some(s.to_ascii_lowercase()), r),
        None => (None, text),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (name, port) = if authority.starts_with('[') {
        match authority.split_once("]:") {
            Some((h, p)) => (format!("{h}]"), p.parse().ok()),
            None => (authority.to_string(), None),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
                (h.to_string(), p.parse().ok())
            }
            _ => (authority.to_string(), None),
        }
    };
    let name = name.to_ascii_lowercase().trim_end_matches('.').to_string();
    if !HOSTLIKE.is_match(&name) {
        return None;
    }
    // Without a scheme, `file.txt` looks like a host. Require a plausible TLD.
    if scheme.is_none() {
        let tld = name.rsplit('.').next().unwrap_or("");
        const FILE_EXTS: &[&str] = &[
            "txt", "json", "sh", "md", "js", "ts", "py", "rs", "yml", "yaml", "toml", "log",
            "html", "css", "xml", "csv", "zip", "gz", "tgz", "tar", "png", "jpg", "pdf", "lock",
            "env", "cfg", "ini", "conf",
        ];
        if FILE_EXTS.contains(&tld) {
            return None;
        }
    }
    Some(Host { name, port, scheme })
}

fn parse_git_url(text: &str) -> Option<Host> {
    if text.contains("://") {
        return parse_host(text);
    }
    // scp-like: git@github.com:org/repo.git
    let (user_host, path) = text.split_once(':')?;
    if path.starts_with("//") || user_host.contains('/') || !user_host.contains('@') {
        return None;
    }
    parse_host(&format!("ssh://{user_host}"))
}

fn uploads(scope: &Scope, inv: &Invocation, hosts: &[Host], out: &mut Out) {
    let dest = hosts
        .first()
        .map(|h| h.name.clone())
        .unwrap_or_else(|| "a remote host".into());
    let mut files: Vec<String> = Vec::new();
    match inv.exe.as_str() {
        "curl" => {
            let args = inv.args();
            for (i, w) in args.iter().enumerate() {
                let t = w.text.as_str();
                let value = |name: &str| -> Option<String> {
                    if t == name {
                        args.get(i + 1).map(|w| w.text.clone())
                    } else {
                        t.strip_prefix(&format!("{name}=")).map(str::to_string)
                    }
                };
                for name in ["-T", "--upload-file"] {
                    if let Some(v) = value(name) {
                        files.push(v);
                    }
                }
                for name in [
                    "-d",
                    "--data",
                    "--data-binary",
                    "--data-urlencode",
                    "--json",
                ] {
                    if let Some(v) = value(name) {
                        if let Some(f) = v
                            .split_once('@')
                            .map(|(_, f)| f)
                            .filter(|f| !f.is_empty() && *f != "-")
                        {
                            if v.starts_with('@') || name == "--data-urlencode" {
                                files.push(f.to_string());
                            }
                        }
                    }
                }
                for name in ["-F", "--form"] {
                    if let Some(v) = value(name) {
                        if let Some((_, f)) = v.split_once("=@").or_else(|| v.split_once("=<")) {
                            files.push(f.split(';').next().unwrap_or(f).to_string());
                        }
                    }
                }
            }
        }
        "wget" => {
            if let Some(f) = option_value(inv, &["--post-file", "--body-file"]) {
                files.push(f);
            }
        }
        "http" | "https" | "xh" | "xhs" => {
            for w in inv.args() {
                if let Some((_, f)) = w.text.split_once("@") {
                    if !w.text.contains("://") && !f.is_empty() {
                        files.push(f.to_string());
                    }
                }
            }
        }
        "scp" | "rsync" | "rclone" => {
            let pos = inv.positionals();
            if let Some((last, sources)) = pos.split_last() {
                let remote = |t: &str| {
                    t.contains("://")
                        || t.split_once(':')
                            .is_some_and(|(h, _)| !h.is_empty() && !h.contains('/'))
                };
                if remote(&last.text) {
                    files.extend(
                        sources
                            .iter()
                            .filter(|s| !remote(&s.text))
                            .map(|s| s.text.clone()),
                    );
                }
            }
        }
        "nc" | "ncat" | "netcat" | "socat" | "telnet" => {
            if let Some((text, _)) = scope.redirect_reads(inv).into_iter().next() {
                files.push(text);
            } else if inv.stdin_piped && !inv.has_flag(Some('l'), &["--listen"]) {
                files.push("piped data".into());
            }
        }
        "aws" => {
            let pos: Vec<&str> = inv.positionals().iter().map(|w| w.text.as_str()).collect();
            if pos.first() == Some(&"s3")
                && matches!(pos.get(1), Some(&"cp") | Some(&"sync") | Some(&"mv"))
                && pos.len() > 3
                && pos.last().is_some_and(|l| l.starts_with("s3://"))
            {
                files.extend(
                    pos[2..pos.len() - 1]
                        .iter()
                        .filter(|p| !p.starts_with("s3://"))
                        .map(|s| s.to_string()),
                );
            }
        }
        "gsutil" => {
            let pos: Vec<&str> = inv.positionals().iter().map(|w| w.text.as_str()).collect();
            if pos.len() > 2
                && matches!(pos.first(), Some(&"cp") | Some(&"rsync") | Some(&"mv"))
                && pos.last().is_some_and(|l| l.starts_with("gs://"))
            {
                files.extend(
                    pos[1..pos.len() - 1]
                        .iter()
                        .filter(|p| !p.starts_with("gs://"))
                        .map(|s| s.to_string()),
                );
            }
        }
        _ => {}
    }
    if !files.is_empty() {
        out.push(
            Finding::new(
                "net.upload",
                Risk::High,
                format!("Uploads {} to {dest}", files[0]),
            )
            .with_details(files.iter().skip(1).cloned().collect()),
        );
    }
}

fn listeners(inv: &Invocation, out: &mut Out) {
    let exe = inv.exe.as_str();
    let args: Vec<&str> = inv.args().iter().map(|w| w.text.as_str()).collect();
    let msg = match exe {
        "nc" | "ncat" | "netcat" if inv.has_flag(Some('l'), &["--listen"]) => {
            Some((Risk::Medium, "Opens a network listener"))
        }
        "socat"
            if args
                .iter()
                .any(|a| a.to_ascii_uppercase().contains("LISTEN")) =>
        {
            Some((Risk::Medium, "Opens a network listener"))
        }
        e if crate::command::is_python(e)
            && args
                .windows(2)
                .any(|w| w[0] == "-m" && matches!(w[1], "http.server" | "SimpleHTTPServer")) =>
        {
            Some((Risk::Medium, "Serves the current directory over HTTP"))
        }
        "php" if args.first() == Some(&"-S") => Some((Risk::Medium, "Starts a PHP web server")),
        "ngrok" | "cloudflared" | "lt" | "localtunnel" | "bore" => {
            Some((Risk::High, "Exposes a local port to the public internet"))
        }
        "ssh" if inv.has_flag(Some('R'), &[]) => Some((
            Risk::High,
            "Opens a reverse tunnel from a remote host into this machine",
        )),
        _ => None,
    };
    if let Some((risk, message)) = msg {
        out.push(Finding::new("net.listen", risk, message));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts() {
        let h = parse_host("https://user:pw@Example.COM:8443/path?q=1").unwrap();
        assert_eq!(h.name, "example.com");
        assert_eq!(h.port, Some(8443));
        assert_eq!(h.scheme.as_deref(), Some("https"));
        assert_eq!(
            parse_host("registry.npmjs.org/pkg").unwrap().name,
            "registry.npmjs.org"
        );
        assert!(parse_host("output.json").is_none());
        assert!(parse_host("./script.sh").is_none());
        assert_eq!(
            parse_git_url("git@github.com:org/repo.git").unwrap().name,
            "github.com"
        );
        assert!(parse_git_url("src/main.rs").is_none());
    }
}
