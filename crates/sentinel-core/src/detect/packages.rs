use super::{Out, Scope};
use crate::command::{is_python, Invocation};
use crate::{Finding, Risk};

pub(crate) fn detect(scope: &Scope, out: &mut Out) {
    for inv in &scope.set.invocations {
        let pos: Vec<String> = inv.positionals().iter().map(|w| w.text.clone()).collect();
        let sub = pos.first().map(String::as_str).unwrap_or("");
        let rest: Vec<String> = pos.iter().skip(1).cloned().collect();
        match inv.exe.as_str() {
            "npm" => match sub {
                "install" | "i" | "in" | "ins" | "inst" | "insta" | "instal" | "isnt"
                | "isntal" | "isntall" | "add" => add_or_install(inv, "npm", &rest, out),
                "ci" | "update" | "up" | "upgrade" => install(&format!("npm {sub}"), out),
                "exec" | "x" => remote_exec(first_package(&rest), out),
                "init" | "create" if !rest.is_empty() => {
                    remote_exec(Some(&format!("create-{}", rest[0])), out)
                }
                _ => {}
            },
            "npx" | "bunx" | "pnpx" => remote_exec(pos.first().map(String::as_str), out),
            "yarn" => match sub {
                "add" => add_or_install(inv, "yarn", &rest, out),
                "" | "install" => install("yarn install", out),
                "dlx" => remote_exec(first_package(&rest), out),
                "create" => remote_exec(rest.first().map(|s| s.as_str()), out),
                "global" if rest.first().map(String::as_str) == Some("add") => {
                    add_or_install(inv, "yarn global", &rest[1..], out)
                }
                _ => {}
            },
            "pnpm" => match sub {
                "add" | "install" | "i" => add_or_install(inv, "pnpm", &rest, out),
                "dlx" | "create" => remote_exec(first_package(&rest), out),
                _ => {}
            },
            "bun" => match sub {
                "add" | "a" | "install" | "i" => add_or_install(inv, "bun", &rest, out),
                "x" | "create" => remote_exec(first_package(&rest), out),
                _ => {}
            },
            exe if exe.starts_with("pip")
                && exe[3..].chars().all(|c| c.is_ascii_digit() || c == '.') =>
            {
                pip(inv, &pos, out)
            }
            exe if is_python(exe)
                && inv
                    .args()
                    .windows(2)
                    .any(|w| w[0].text == "-m" && w[1].text.starts_with("pip")) =>
            {
                let after: Vec<String> = pos
                    .iter()
                    .skip_while(|p| !p.starts_with("pip"))
                    .skip(1)
                    .cloned()
                    .collect();
                pip(inv, &after, out);
            }
            "uv" => match sub {
                "add" => add_or_install(inv, "uv", &rest, out),
                "pip" => pip(inv, &rest, out),
                "sync" | "lock" => install(&format!("uv {sub}"), out),
                "tool" => match rest.first().map(String::as_str) {
                    Some("install") => add_or_install(inv, "uv tool", &rest[1..], out),
                    Some("run") => remote_exec(rest.get(1).map(String::as_str), out),
                    _ => {}
                },
                _ => {}
            },
            "uvx" => remote_exec(pos.first().map(String::as_str), out),
            "pipx" => match sub {
                "install" => add_or_install(inv, "pipx", &rest, out),
                "run" => remote_exec(rest.first().map(String::as_str), out),
                _ => {}
            },
            "poetry" | "pdm" | "rye" | "hatch" => match sub {
                "add" => add_or_install(inv, inv.exe.as_str(), &rest, out),
                "install" | "sync" | "lock" => install(&format!("{} {sub}", inv.exe), out),
                _ => {}
            },
            "conda" | "mamba" | "micromamba" if sub == "install" => {
                add_or_install(inv, inv.exe.as_str(), &rest, out)
            }
            "cargo" => match sub {
                "add" | "install" | "binstall" => {
                    let untrusted = inv.has_flag(None, &["--git"]);
                    package_add(&format!("cargo {sub}"), &rest, untrusted, out)
                }
                _ => {}
            },
            "go" => match sub {
                "get" => package_add("go get", &rest, false, out),
                "install" if rest.iter().any(|r| r.contains('@')) => {
                    package_add("go install", &rest, false, out)
                }
                "run" if rest.first().is_some_and(|r| r.contains('@')) => {
                    remote_exec(rest.first().map(String::as_str), out)
                }
                _ => {}
            },
            "gem" if sub == "install" => package_add("gem install", &rest, false, out),
            "bundle" => match sub {
                "add" => package_add("bundle add", &rest, false, out),
                "install" | "update" => install(&format!("bundle {sub}"), out),
                _ => {}
            },
            "composer" => match sub {
                "require" => package_add("composer require", &rest, false, out),
                "install" | "update" => install(&format!("composer {sub}"), out),
                _ => {}
            },
            "brew" if matches!(sub, "install" | "reinstall" | "tap") => {
                package_add(&format!("brew {sub}"), &rest, false, out)
            }
            "apt" | "apt-get" | "aptitude" | "yum" | "dnf" | "zypper" | "port" | "snap"
            | "flatpak" | "choco" | "winget" | "scoop" | "nix-env"
                if sub == "install"
                    || (inv.exe == "nix-env" && inv.has_flag(Some('i'), &["--install"])) =>
            {
                package_add(&format!("{} install", inv.exe), &rest, false, out)
            }
            "apk" if sub == "add" => package_add("apk add", &rest, false, out),
            "pacman" => {
                let sync = inv.args().iter().any(|w| {
                    let t = w.text.as_str();
                    t.starts_with("-S") && !t[2..].contains(['s', 'i', 'l', 'g', 'c'])
                });
                if sync {
                    package_add("pacman -S", &pos, false, out);
                }
            }
            "dotnet" if sub == "add" && rest.first().map(String::as_str) == Some("package") => {
                package_add("dotnet add package", &rest[1..], false, out)
            }
            "deno" => match sub {
                "add" | "install" => package_add(&format!("deno {sub}"), &rest, false, out),
                "run"
                    if rest.first().is_some_and(|r| {
                        r.contains("://") || r.starts_with("npm:") || r.starts_with("jsr:")
                    }) =>
                {
                    remote_exec(rest.first().map(String::as_str), out)
                }
                _ => {}
            },
            _ => {}
        }
    }
}

fn first_package(args: &[String]) -> Option<&str> {
    args.iter()
        .map(String::as_str)
        .find(|a| !a.starts_with('-'))
}

fn is_untrusted_source(spec: &str) -> bool {
    spec.contains("://")
        || spec.starts_with("git+")
        || spec.starts_with("github:")
        || spec.starts_with("gitlab:")
        || spec.starts_with("bitbucket:")
        || spec.ends_with(".tgz")
        || spec.ends_with(".tar.gz")
        || (spec.contains('/') && spec.contains('#'))
}

fn add_or_install(inv: &Invocation, tool: &str, names: &[String], out: &mut Out) {
    if names.is_empty() {
        install(&format!("{tool} install"), out);
        return;
    }
    let global = inv.has_flag(Some('g'), &["--global", "--location=global"]);
    let label = if global {
        format!("{tool} (global)")
    } else {
        tool.to_string()
    };
    let untrusted = names.iter().any(|n| is_untrusted_source(n));
    package_add(&label, names, untrusted, out);
}

fn package_add(tool: &str, names: &[String], untrusted: bool, out: &mut Out) {
    let names: Vec<&String> = names.iter().filter(|n| !n.starts_with('-')).collect();
    if names.is_empty() {
        return;
    }
    let list: Vec<&str> = names.iter().take(5).map(|s| s.as_str()).collect();
    let mut text = list.join(", ");
    if names.len() > 5 {
        text.push_str(&format!(" (+{} more)", names.len() - 5));
    }
    if untrusted {
        out.push(Finding::new(
            "pkg.add",
            Risk::High,
            format!("{tool} installs from an unverified source: {text}"),
        ));
    } else {
        out.push(Finding::new(
            "pkg.add",
            Risk::Medium,
            format!("{tool} adds {text}"),
        ));
    }
}

fn install(what: &str, out: &mut Out) {
    out.push(Finding::new(
        "pkg.install",
        Risk::Low,
        format!("{what} installs dependencies from the manifest"),
    ));
}

fn remote_exec(package: Option<&str>, out: &mut Out) {
    let what = package.unwrap_or("a package");
    out.push(Finding::new(
        "pkg.remote-exec",
        Risk::Medium,
        format!("Downloads and runs {what}"),
    ));
}

fn pip(inv: &Invocation, args: &[String], out: &mut Out) {
    if args.first().map(String::as_str) != Some("install") {
        return;
    }
    let from_file = inv.has_flag(Some('r'), &["--requirement"])
        || inv.has_flag(None, &["-e", "--editable"]) && args.len() <= 2;
    let names: Vec<String> = args
        .iter()
        .skip(1)
        .filter(|a| !matches!(a.as_str(), "." | "./"))
        .cloned()
        .collect();
    if from_file || names.is_empty() {
        install("pip install", out);
        return;
    }
    // `-r file` values are positionals too; drop names that are requirement files.
    let names: Vec<String> = names.into_iter().filter(|n| !n.ends_with(".txt")).collect();
    if names.is_empty() {
        install("pip install", out);
        return;
    }
    let untrusted = names.iter().any(|n| is_untrusted_source(n));
    package_add(&format!("{} install", inv.exe), &names, untrusted, out);
}
