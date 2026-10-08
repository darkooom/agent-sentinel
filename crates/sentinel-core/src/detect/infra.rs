use std::sync::LazyLock;

use regex::Regex;

use super::{Out, Scope};
use crate::command::Invocation;
use crate::shell::RedirectKind;
use crate::{Finding, Risk};

pub(crate) fn detect(scope: &Scope, out: &mut Out) {
    for inv in &scope.set.invocations {
        if let Some((risk, message)) = destructive(inv) {
            let (risk, message) = match production_marker(inv) {
                Some(marker) => (
                    Risk::Critical,
                    format!("{message} (targets production: {marker})"),
                ),
                None => (risk, message),
            };
            out.push(Finding::new("infra.destructive", risk, message));
        }
    }
}

/// Global options of infrastructure CLIs that take a separate value.
const VALUE_OPTIONS: &[&str] = &[
    "--context",
    "-n",
    "--namespace",
    "--kubeconfig",
    "--cluster",
    "--user",
    "-l",
    "--selector",
    "-o",
    "--output",
    "-f",
    "--filename",
    "-c",
    "--container",
    "--profile",
    "--region",
    "--project",
    "-p",
    "--stack",
    "-s",
    "--chdir",
    "-var",
    "-var-file",
    "--app",
    "-a",
    "--account",
    "--subscription",
    "-g",
    "--resource-group",
    "--endpoint-url",
    "-h",
    "--host",
    "-U",
    "--username",
    "-d",
    "--dbname",
];

fn positionals(inv: &Invocation) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for w in inv.args() {
        let t = w.text.as_str();
        if skip {
            skip = false;
            continue;
        }
        if VALUE_OPTIONS.contains(&t) {
            skip = true;
            continue;
        }
        if t.starts_with('-') && t.len() > 1 {
            continue;
        }
        out.push(t.to_ascii_lowercase());
    }
    out
}

fn destructive(inv: &Invocation) -> Option<(Risk, String)> {
    let pos = positionals(inv);
    let p = |i: usize| pos.get(i).map(String::as_str).unwrap_or("");
    let has = |a: &str| pos.iter().any(|x| x == a);
    let flag = |f: &[&str]| inv.has_flag(None, f);
    let exe = inv.exe.as_str();
    match exe {
        "terraform" | "tofu" | "terragrunt" => match p(0) {
            "destroy" => Some((
                Risk::Critical,
                format!("{exe} destroy tears down managed infrastructure"),
            )),
            "apply" if flag(&["-destroy", "--destroy"]) => Some((
                Risk::Critical,
                format!("{exe} apply -destroy tears down infrastructure"),
            )),
            "apply" if flag(&["-auto-approve", "--auto-approve"]) => Some((
                Risk::High,
                format!("{exe} apply -auto-approve changes infrastructure without review"),
            )),
            "state" if matches!(p(1), "rm" | "push" | "replace-provider") => Some((
                Risk::High,
                format!("{exe} state {} rewrites infrastructure state", p(1)),
            )),
            "workspace" if p(1) == "delete" => {
                Some((Risk::High, format!("{exe} workspace delete")))
            }
            _ => None,
        },
        "pulumi" => match p(0) {
            "destroy" | "down" => {
                Some((Risk::Critical, "pulumi destroy tears down a stack".into()))
            }
            "up" | "update" if inv.has_flag(Some('y'), &["--yes"]) => Some((
                Risk::High,
                "pulumi up --yes changes infrastructure without review".into(),
            )),
            "stack" if p(1) == "rm" => Some((Risk::High, "pulumi stack rm deletes a stack".into())),
            _ => None,
        },
        "kubectl" | "oc" => match p(0) {
            "delete" => {
                if flag(&["--all", "--all-namespaces"])
                    || inv.has_flag(Some('A'), &[])
                    || matches!(p(1), "namespace" | "ns" | "namespaces")
                {
                    Some((
                        Risk::Critical,
                        format!(
                            "kubectl delete {} removes entire namespaces or all resources",
                            p(1)
                        ),
                    ))
                } else {
                    Some((
                        Risk::High,
                        format!("kubectl delete {} {}", p(1), p(2))
                            .trim_end()
                            .to_string(),
                    ))
                }
            }
            "drain" => Some((
                Risk::High,
                "kubectl drain evicts every pod from a node".into(),
            )),
            "replace" if flag(&["--force"]) => Some((
                Risk::High,
                "kubectl replace --force deletes and recreates resources".into(),
            )),
            "apply" if flag(&["--prune"]) => Some((
                Risk::High,
                "kubectl apply --prune deletes resources missing from the manifest".into(),
            )),
            _ => None,
        },
        "helm" if matches!(p(0), "uninstall" | "delete" | "del" | "un") => {
            Some((Risk::High, format!("helm {} removes a release", p(0))))
        }
        "aws" => {
            let (service, action) = (p(0), p(1));
            if service == "s3" && action == "rm" && flag(&["--recursive"]) {
                Some((
                    Risk::Critical,
                    "aws s3 rm --recursive deletes every object under a prefix".into(),
                ))
            } else if service == "s3" && action == "rb" {
                Some((Risk::High, "aws s3 rb deletes a bucket".into()))
            } else if [
                "delete-",
                "terminate-",
                "remove-",
                "deregister-",
                "purge-",
                "destroy-",
            ]
            .iter()
            .any(|v| action.starts_with(v))
            {
                Some((Risk::High, format!("aws {service} {action}")))
            } else {
                None
            }
        }
        "gcloud" | "az" if has("delete") => {
            let what = pos
                .iter()
                .take_while(|x| *x != "delete")
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            let risk = if exe == "az" && p(0) == "group" {
                Risk::Critical
            } else {
                Risk::High
            };
            Some((risk, format!("{exe} {what} delete")))
        }
        "gh" if p(0) == "repo" && p(1) == "delete" => Some((
            Risk::Critical,
            "gh repo delete permanently deletes a repository".into(),
        )),
        "gh" if p(0) == "release" && p(1) == "delete" => {
            Some((Risk::High, "gh release delete".into()))
        }
        "heroku" if matches!(p(0), "apps:destroy" | "apps:delete" | "destroy") => {
            Some((Risk::Critical, "heroku apps:destroy deletes an app".into()))
        }
        "heroku" if p(0) == "pg:reset" => {
            Some((Risk::Critical, "heroku pg:reset wipes a database".into()))
        }
        "fly" | "flyctl" if p(0) == "destroy" || (p(0) == "apps" && p(1) == "destroy") => {
            Some((Risk::Critical, "fly destroy deletes an app".into()))
        }
        "vercel" if matches!(p(0), "remove" | "rm") => {
            Some((Risk::High, "vercel remove deletes deployments".into()))
        }
        "docker" | "podman" => match p(0) {
            "system" | "volume" | "image" | "container" | "network" | "builder"
                if p(1) == "prune" =>
            {
                let risk = if p(0) == "volume" || p(0) == "system" && flag(&["--volumes"]) {
                    Risk::High
                } else {
                    Risk::Medium
                };
                (risk >= Risk::High)
                    .then(|| (risk, format!("{exe} {} prune deletes data volumes", p(0))))
            }
            "volume" if matches!(p(1), "rm" | "remove") => Some((
                Risk::High,
                format!("{exe} volume rm deletes persistent data"),
            )),
            "compose" if p(1) == "down" && inv.has_flag(Some('v'), &["--volumes"]) => {
                Some((Risk::High, "docker compose down -v deletes volumes".into()))
            }
            _ => None,
        },
        "docker-compose" if p(0) == "down" && inv.has_flag(Some('v'), &["--volumes"]) => {
            Some((Risk::High, "docker-compose down -v deletes volumes".into()))
        }
        "dropdb" | "dropuser" => Some((
            Risk::High,
            format!("{exe} permanently deletes a database object"),
        )),
        "redis-cli" if has("flushall") || has("flushdb") => {
            Some((Risk::High, "redis-cli FLUSHALL deletes every key".into()))
        }
        "psql" | "mysql" | "mariadb" | "sqlite3" | "sqlcmd" | "mongosh" | "mongo" | "cockroach"
        | "clickhouse-client" | "duckdb" => sql_text(inv)
            .and_then(|sql| destructive_sql(&sql))
            .map(|what| (Risk::High, format!("{exe}: {what}"))),
        _ => None,
    }
}

fn sql_text(inv: &Invocation) -> Option<String> {
    let mut text = String::new();
    let args = inv.args();
    for (i, w) in args.iter().enumerate() {
        if matches!(
            w.text.as_str(),
            "-c" | "--command" | "-e" | "--execute" | "--eval" | "-q" | "-Q" | "--query"
        ) {
            if let Some(v) = args.get(i + 1) {
                text.push_str(&v.text);
                text.push('\n');
            }
        }
    }
    if inv.exe == "sqlite3" || inv.exe == "duckdb" {
        for w in inv.positionals().iter().skip(1) {
            text.push_str(&w.text);
            text.push('\n');
        }
    }
    for r in &inv.redirects {
        match r.kind {
            RedirectKind::Heredoc => text.push_str(r.body.as_deref().unwrap_or("")),
            RedirectKind::HereString => text.push_str(&r.target.text),
            _ => {}
        }
    }
    (!text.is_empty()).then_some(text)
}

fn destructive_sql(sql: &str) -> Option<&'static str> {
    static DROP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\bdrop\s+(?:table|database|schema|collection|index|view|user)\b|\bdropDatabase\s*\(|\.drop\s*\(").expect("valid regex")
    });
    static TRUNCATE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\btruncate\b").expect("valid regex"));
    static DELETE_ALL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)\bdelete\s+from\s+[\w.`\x22\[\]]+\s*(?:;|$)|\bdeleteMany\s*\(\s*\{\s*\}\s*\)",
        )
        .expect("valid regex")
    });
    static UPDATE_ALL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\bupdate\s+[\w.`\x22\[\]]+\s+set\s+[^;]*?(?:;|$)").expect("valid regex")
    });
    if DROP.is_match(sql) {
        Some("drops a table or database")
    } else if TRUNCATE.is_match(sql) {
        Some("truncates a table")
    } else if DELETE_ALL.is_match(sql) {
        Some("deletes every row (DELETE without WHERE)")
    } else if UPDATE_ALL
        .find(sql)
        .is_some_and(|m| !m.as_str().to_ascii_lowercase().contains(" where "))
    {
        Some("updates every row (UPDATE without WHERE)")
    } else {
        None
    }
}

/// An argument or assignment that names a production environment.
fn production_marker(inv: &Invocation) -> Option<String> {
    static PROD: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(?:^|[^a-z])(prod|production|prd|live)(?:$|[^a-z])").expect("valid regex")
    });
    inv.args()
        .iter()
        .map(|w| w.text.as_str())
        .chain(inv.assignments.iter().map(|(_, v)| v.text.as_str()))
        .find(|t| PROD.is_match(t) && !t.starts_with("--prod=false"))
        .map(str::to_string)
}
