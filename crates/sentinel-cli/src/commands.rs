use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use sentinel_audit::{filter, AuditLog, Filter, Outcome};
use sentinel_core::display::sanitize_line;
use sentinel_core::{catalog, secrets, Action};
use sentinel_policy::{PolicySource, Verdict, DEFAULT_POLICY};
use sentinel_runtime::adapters::{self, generic};
use sentinel_runtime::discovery::{load_file, POLICY_DIR, POLICY_FILE};
use sentinel_runtime::exec::Invocation;
use sentinel_runtime::install::{claude_hook_locations, install_claude_hook, InstallResult};
use sentinel_runtime::session::Sessions;
use sentinel_runtime::{Engine, Evaluation, Paths};
use unicode_width::UnicodeWidthStr;

use crate::ui::{self, risk_color, tilde, verdict_color, Answer, Color, NoPrompt, Painter};
use crate::EXIT_BLOCKED;

fn cwd() -> Result<std::path::PathBuf> {
    std::env::current_dir().context("cannot determine the current directory")
}

fn record(engine: &Engine, action: &Action, eval: &Evaluation, outcome: Outcome) {
    if let Err(e) = engine.record(action, eval, outcome) {
        let p = Painter::stderr();
        eprintln!(
            "{} could not write audit log: {e:#}",
            p.paint(Color::Yellow, "warning:")
        );
    }
}

// ------------------------------------------------------------------- init

pub fn init(force: bool, claude_code: bool) -> Result<ExitCode> {
    let cwd = cwd()?;
    let p = Painter::stdout();
    let file = cwd.join(POLICY_DIR).join(POLICY_FILE);
    if file.exists() && !force {
        if !claude_code {
            bail!(".sentinel/policy.yml already exists (use --force to replace it)");
        }
        println!(
            "{} keeping existing .sentinel/policy.yml",
            p.paint(Color::Dim, "·")
        );
    } else {
        std::fs::create_dir_all(file.parent().expect("has parent"))?;
        std::fs::write(&file, DEFAULT_POLICY)?;
        println!(
            "{} created .sentinel/policy.yml",
            p.paint(Color::Green, "✓")
        );
    }
    if claude_code {
        let exe = std::env::current_exe()
            .and_then(|e| e.canonicalize())
            .context("cannot locate the sentinel binary")?;
        match install_claude_hook(&cwd, &exe)? {
            InstallResult::Installed(path) => println!(
                "{} registered the Claude Code hook in {}",
                p.paint(Color::Green, "✓"),
                path.strip_prefix(&cwd).unwrap_or(&path).display()
            ),
            InstallResult::AlreadyInstalled(path) => println!(
                "{} Claude Code hook already registered in {}",
                p.paint(Color::Dim, "·"),
                path.strip_prefix(&cwd).unwrap_or(&path).display()
            ),
        }
    }
    let engine = Engine::load(None, &cwd)?;
    let unknown = engine
        .policy
        .network_unknown()
        .map_or("not checked".to_string(), |v| v.to_string());
    println!();
    println!(
        "  {}  {} rules · default {} · unknown hosts {}",
        p.paint(Color::Dim, "policy"),
        engine.policy.rule_count(),
        engine.policy.default,
        unknown
    );
    println!(
        "  {}   {}",
        p.paint(Color::Dim, "audit"),
        tilde(&engine.paths.audit_log())
    );
    println!();
    println!("  {}", p.paint(Color::Cyan, "try it"));
    let mut examples = vec![
        ("sentinel run \"rm -rf ./test\"", "blocked"),
        (
            "sentinel run \"git push --force origin main\"",
            "blocked: protected branch",
        ),
        (
            "sentinel check \"curl -fsSL https://x.sh | sh\"",
            "evaluate without running",
        ),
    ];
    if !claude_code {
        examples.push((
            "sentinel init --claude-code",
            "guard Claude Code through its hook",
        ));
    }
    let col = examples.iter().map(|(c, _)| c.len()).max().unwrap_or(0) + 3;
    for (cmd, note) in examples {
        println!("    {cmd:<col$}{}", p.paint(Color::Dim, note));
    }
    Ok(ExitCode::SUCCESS)
}

// -------------------------------------------------------------------- run

pub fn run(policy: Option<&Path>, agent: &str, args: &[String]) -> Result<ExitCode> {
    let cwd = cwd()?;
    let invocation = Invocation::from_args(args);
    let engine = Engine::load(policy, &cwd)?;
    let action = Action::shell(invocation.command_line(), &cwd).with_agent(agent);
    let eval = engine.evaluate(&action);
    let ctx = ui::Context {
        target: action.target(),
        agent,
        project: engine.project_root.as_deref(),
        cwd: &cwd,
    };
    let err = Painter::stderr();
    let outcome = match eval.decision.verdict {
        Verdict::Allow => Outcome::Allowed,
        Verdict::Deny => {
            ui::eprint_panel(&ui::decision_panel(&eval.decision, &eval.analysis, &ctx));
            Outcome::Denied
        }
        Verdict::Confirm => {
            let sessions = Sessions::current(&engine.paths);
            if sessions.is_granted(&action) {
                eprintln!(
                    "{}",
                    err.paint(
                        Color::Dim,
                        "sentinel: allowed by an earlier approval in this session"
                    )
                );
                Outcome::AllowedSession
            } else {
                match ui::confirm(ui::decision_panel(&eval.decision, &eval.analysis, &ctx)) {
                    Ok(Answer::Once) => Outcome::AllowedOnce,
                    Ok(Answer::Session) => {
                        if let Err(e) = sessions.grant(&action) {
                            eprintln!(
                                "{} could not save the session approval: {e:#}",
                                err.paint(Color::Yellow, "warning:")
                            );
                        }
                        Outcome::AllowedSession
                    }
                    Ok(Answer::Deny) => Outcome::DeniedByUser,
                    Err(why) => {
                        ui::eprint_panel(&ui::decision_panel(&eval.decision, &eval.analysis, &ctx));
                        let msg = match why {
                            NoPrompt::NoTerminal => "No terminal to ask on, so this was denied (confirmations fail closed).".to_string(),
                            NoPrompt::InsideAgent(name) => format!(
                                "Running inside {name}, which owns the terminal, so this was denied. Inside agents, confirmations go through the agent's own prompt: `sentinel init --claude-code`."
                            ),
                        };
                        eprintln!("  {}", err.paint(Color::Yellow, &msg));
                        Outcome::DeniedNoTerminal
                    }
                }
            }
        }
    };
    record(&engine, &action, &eval, outcome);
    if outcome.is_denied() {
        return Ok(ExitCode::from(EXIT_BLOCKED));
    }
    if invocation.is_interactive_shell() {
        eprintln!(
            "{}",
            err.paint(Color::Dim, "sentinel: starting an interactive shell. Commands typed inside it are NOT inspected.")
        );
    }
    let _ = std::io::stderr().flush();
    let program = args.first().map(String::as_str).unwrap_or("");
    match invocation.exec() {
        Ok(code) => Ok(ExitCode::from(u8::try_from(code).unwrap_or(1))),
        Err(e) => {
            eprintln!("sentinel: cannot run `{}`: {e}", sanitize_line(program));
            Ok(ExitCode::from(127))
        }
    }
}

// ------------------------------------------------------------------ check

pub fn check(
    policy: Option<&Path>,
    agent: &str,
    json: bool,
    read: Option<String>,
    write: Option<String>,
    fetch: Option<String>,
    command: &[String],
) -> Result<ExitCode> {
    let cwd = cwd()?;
    let action = if let Some(path) = read {
        Action::file_read(path, &cwd)
    } else if let Some(path) = write {
        Action::file_write(path, None, &cwd)
    } else if let Some(url) = fetch {
        Action::network(url, &cwd)
    } else if command.is_empty() {
        bail!("nothing to check: pass a command, --read PATH, --write PATH or --fetch URL");
    } else {
        Action::shell(Invocation::from_args(command).command_line(), &cwd)
    }
    .with_agent(agent);
    let engine = Engine::load(policy, &cwd)?;
    let eval = engine.evaluate(&action);
    record(&engine, &action, &eval, Outcome::Checked);
    let code = ExitCode::from(generic::exit_code(eval.decision.verdict) as u8);

    if json {
        let body = serde_json::json!({
            "decision": eval.decision.verdict,
            "reason": secrets::redact(&eval.decision.reason),
            "rule": eval.decision.rule,
            "risk": eval.decision.risk,
            "matched": eval.decision.matched,
            "findings": eval.analysis.findings,
            "facts": eval.analysis.facts,
            "policy": engine.policy.source.to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&body)?);
        return Ok(code);
    }

    let p = Painter::stdout();
    if eval.decision.verdict == Verdict::Allow {
        println!(
            "{}  {}",
            p.paint(Color::Green, "✓ allowed"),
            p.paint(
                Color::Bold,
                &sanitize_line(&secrets::redact(action.target()))
            )
        );
        println!(
            "  {}",
            p.paint(
                Color::Dim,
                &format!(
                    "risk {} · {}",
                    eval.decision.risk,
                    sanitize_line(&eval.decision.reason)
                )
            )
        );
    } else {
        let ctx = ui::Context {
            target: action.target(),
            agent,
            project: engine.project_root.as_deref(),
            cwd: &cwd,
        };
        print!(
            "{}",
            ui::decision_panel(&eval.decision, &eval.analysis, &ctx).render(&p)
        );
    }
    if !eval.analysis.findings.is_empty() {
        println!("\n  {}", p.paint(Color::Cyan, "findings"));
        for f in &eval.analysis.findings {
            println!(
                "    {}  {:<24} {}",
                p.paint(risk_color(f.risk), &format!("{:<8}", f.risk.as_str())),
                f.id,
                sanitize_line(&f.message)
            );
        }
    }
    if !eval.decision.matched.is_empty() {
        println!("\n  {}", p.paint(Color::Cyan, "rules"));
        for m in &eval.decision.matched {
            println!(
                "    {}  {}",
                p.paint(
                    verdict_color(m.verdict),
                    &format!("{:<8}", m.verdict.as_str())
                ),
                m.rule
            );
        }
    }
    Ok(code)
}

// -------------------------------------------------------------------- log

fn outcome_label(outcome: Outcome, decision: Verdict) -> (String, Color) {
    match outcome {
        Outcome::Allowed => ("✓ allowed".into(), Color::Green),
        Outcome::AllowedOnce => ("✓ approved".into(), Color::Green),
        Outcome::AllowedSession => ("✓ session".into(), Color::Green),
        Outcome::Denied => ("✖ blocked".into(), Color::Red),
        Outcome::DeniedByUser => ("✖ declined".into(), Color::Red),
        Outcome::DeniedNoTerminal => ("✖ no tty".into(), Color::Red),
        Outcome::Asked => ("⚠ asked".into(), Color::Yellow),
        Outcome::Checked => (format!("· {}", decision.as_str()), Color::Dim),
    }
}

pub fn log(
    today: bool,
    denied: bool,
    agent: Option<String>,
    json: bool,
    limit: Option<usize>,
) -> Result<ExitCode> {
    let paths = Paths::discover();
    let log = AuditLog::new(paths.audit_log());
    let (events, malformed) = log
        .read()
        .with_context(|| format!("cannot read {}", log.path().display()))?;
    let events = filter(
        events,
        &Filter {
            today,
            denied,
            agent,
            limit,
        },
    );
    let mut out = std::io::stdout().lock();
    if json {
        for e in &events {
            writeln!(out, "{}", e.to_json_line())?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    let p = Painter::stdout();
    if events.is_empty() {
        writeln!(
            out,
            "{}",
            p.paint(
                Color::Dim,
                &format!("no matching events  (log: {})", tilde(log.path()))
            )
        )?;
        return Ok(ExitCode::SUCCESS);
    }
    let width = ui::term_width().max(60);
    writeln!(
        out,
        "{}",
        p.paint(
            Color::Dim,
            &format!(
                "{:<14}  {:<12}  {:<11}  {:<8}  ACTION",
                "TIME", "AGENT", "OUTCOME", "RISK"
            )
        )
    )?;
    let now = chrono::Local::now().date_naive();
    for e in &events {
        let local = e.timestamp.with_timezone(&chrono::Local);
        let time = if local.date_naive() == now {
            local.format("%H:%M:%S").to_string()
        } else {
            local.format("%m-%d %H:%M").to_string()
        };
        let (label, color) = outcome_label(e.outcome, e.decision);
        let agent = truncate(&sanitize_line(&e.agent), 12);
        let fixed = 14 + 2 + 12 + 2 + 11 + 2 + 8 + 2;
        let shown = match (&e.command, &e.path) {
            (None, Some(path)) => Path::new(path)
                .strip_prefix(&e.cwd)
                .map(|rel| format!("{} ./{}", e.action.replace("file_", ""), rel.display()))
                .unwrap_or_else(|_| {
                    format!(
                        "{} {}",
                        e.action.replace("file_", ""),
                        tilde(Path::new(path))
                    )
                }),
            (None, None) if e.url.is_some() => format!("fetch {}", e.target()),
            _ => e.target().to_string(),
        };
        let target = truncate(&sanitize_line(&shown), width.saturating_sub(fixed).max(20));
        writeln!(
            out,
            "{:<14}  {:<12}  {}  {}  {}",
            time,
            agent,
            p.paint(color, &pad(&label, 11)),
            p.paint(risk_color(e.risk), &pad(e.risk.as_str(), 8)),
            target
        )?;
    }
    if malformed > 0 {
        writeln!(
            out,
            "{}",
            p.paint(
                Color::Dim,
                &format!("({malformed} unreadable lines skipped)")
            )
        )?;
    }
    Ok(ExitCode::SUCCESS)
}

fn pad(s: &str, width: usize) -> String {
    let w = s.width();
    format!("{s}{}", " ".repeat(width.saturating_sub(w)))
}

fn truncate(s: &str, max: usize) -> String {
    if s.width() <= max {
        return s.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let w = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if used + w + 1 > max {
            break;
        }
        out.push(c);
        used += w;
    }
    out.push('…');
    out
}

// ----------------------------------------------------------------- status

pub fn status(policy: Option<&Path>) -> Result<ExitCode> {
    let cwd = cwd()?;
    let engine = Engine::load(policy, &cwd)?;
    let p = Painter::stdout();
    let label = |s: &str| p.paint(Color::Dim, &format!("{s:<12}"));
    println!(
        "{} {}",
        p.paint(Color::Bold, "agent-sentinel"),
        env!("CARGO_PKG_VERSION")
    );
    println!();
    let source = match &engine.policy.source {
        PolicySource::Builtin => "built-in default (run `sentinel init` to customize)".to_string(),
        PolicySource::File(path) => tilde(path),
    };
    println!("  {}{source}", label("policy"));
    println!(
        "  {}{} rules · default {} · unknown hosts {}",
        label(""),
        engine.policy.rule_count(),
        engine.policy.default,
        engine
            .policy
            .network_unknown()
            .map_or("not checked".into(), |v| v.to_string())
    );
    if let Some(root) = &engine.project_root {
        println!("  {}{}", label("project"), tilde(root));
    }
    println!(
        "  {}{}",
        label("branches"),
        engine.policy.protected_branches.join(", ")
    );
    println!("  {}{}", label("audit"), tilde(&engine.paths.audit_log()));

    let (events, _) = engine.audit_log().read().unwrap_or_default();
    let today = filter(
        events,
        &Filter {
            today: true,
            ..Filter::default()
        },
    );
    let count = |pred: &dyn Fn(Outcome) -> bool| today.iter().filter(|e| pred(e.outcome)).count();
    let allowed = count(&|o| matches!(o, Outcome::Allowed));
    let approved = count(&|o| {
        matches!(
            o,
            Outcome::AllowedOnce | Outcome::AllowedSession | Outcome::Asked
        )
    });
    let blocked = count(&|o| o.is_denied());
    println!(
        "  {}{} · {} · {}",
        label("today"),
        p.paint(Color::Green, &format!("{allowed} allowed")),
        p.paint(Color::Yellow, &format!("{approved} confirmed/asked")),
        p.paint(Color::Red, &format!("{blocked} blocked"))
    );
    let sessions = Sessions::current(&engine.paths);
    println!(
        "  {}{} active approval(s) in this terminal session",
        label("session"),
        sessions.active_count()
    );

    println!();
    println!("  {}", p.paint(Color::Cyan, "integrations"));
    let project = engine.project_root.clone().unwrap_or_else(|| cwd.clone());
    let claude = claude_hook_locations(Some(&project));
    match claude.first() {
        Some(path) => println!(
            "    {:<13}{} hook in {}",
            "claude code",
            p.paint(Color::Green, "✓"),
            tilde(path)
        ),
        None => println!(
            "    {:<13}{} {}",
            "claude code",
            p.paint(Color::Dim, "–"),
            p.paint(Color::Dim, "not registered · sentinel init --claude-code")
        ),
    }
    let codex = codex_hook(&project);
    match codex {
        Some(path) => println!(
            "    {:<13}{} hook in {}",
            "codex",
            p.paint(Color::Green, "✓"),
            tilde(&path)
        ),
        None => println!(
            "    {:<13}{} {}",
            "codex",
            p.paint(Color::Dim, "–"),
            p.paint(Color::Dim, "not registered · docs/integrations.md")
        ),
    }
    println!(
        "    {:<13}{} {}",
        "shell",
        p.paint(Color::Green, "✓"),
        p.paint(Color::Dim, "sentinel run <command>")
    );
    Ok(ExitCode::SUCCESS)
}

fn codex_hook(project: &Path) -> Option<std::path::PathBuf> {
    let mut candidates = vec![
        project.join(".codex/hooks.json"),
        project.join(".codex/config.toml"),
    ];
    if let Some(home) = std::env::home_dir() {
        candidates.push(home.join(".codex/hooks.json"));
        candidates.push(home.join(".codex/config.toml"));
    }
    candidates
        .into_iter()
        .find(|p| std::fs::read_to_string(p).is_ok_and(|t| t.contains("hook codex")))
}

// ----------------------------------------------------------------- policy

pub fn policy_path(policy: Option<&Path>) -> Result<ExitCode> {
    let cwd = cwd()?;
    let engine = Engine::load(policy, &cwd)?;
    match &engine.policy.source {
        PolicySource::File(path) => println!("{}", path.display()),
        PolicySource::Builtin => println!(
            "built-in default (no .sentinel/policy.yml found from {})",
            tilde(&cwd)
        ),
    }
    Ok(ExitCode::SUCCESS)
}

pub fn policy_show(policy: Option<&Path>) -> Result<ExitCode> {
    let cwd = cwd()?;
    let engine = Engine::load(policy, &cwd)?;
    match &engine.policy.source {
        PolicySource::File(path) => print!("{}", std::fs::read_to_string(path)?),
        PolicySource::Builtin => print!("{DEFAULT_POLICY}"),
    }
    Ok(ExitCode::SUCCESS)
}

pub fn policy_validate(file: Option<&Path>) -> Result<ExitCode> {
    let p = Painter::stdout();
    let (policy, name) = match file {
        Some(path) => (load_file(path)?, path.display().to_string()),
        None => {
            let engine = Engine::load(None, &cwd()?)?;
            let name = engine.policy.source.to_string();
            (engine.policy, name)
        }
    };
    println!(
        "{} {name} is valid · {} rules · {} tests",
        p.paint(Color::Green, "✓"),
        policy.rule_count(),
        policy.tests.len()
    );
    Ok(ExitCode::SUCCESS)
}

pub fn policy_test(policy: Option<&Path>) -> Result<ExitCode> {
    let cwd = cwd()?;
    let engine = Engine::load(policy, &cwd)?;
    let p = Painter::stdout();
    if engine.policy.tests.is_empty() {
        println!(
            "{}",
            p.paint(Color::Dim, "the policy has no `tests:` section")
        );
        return Ok(ExitCode::SUCCESS);
    }
    let base = engine.project_root.clone().unwrap_or(cwd);
    let outcomes = engine.policy.run_tests(&base, std::env::home_dir());
    let mut failed = 0;
    for o in &outcomes {
        let target = sanitize_line(&o.target);
        if o.passed() {
            println!(
                "  {}  {:<8} {}",
                p.paint(Color::Green, "✓"),
                o.expected.as_str(),
                target
            );
        } else {
            failed += 1;
            println!(
                "  {}  {:<8} {}   {}",
                p.paint(Color::Red, "✖"),
                o.expected.as_str(),
                target,
                p.paint(
                    Color::Red,
                    &format!(
                        "got {} ({})",
                        o.decision.verdict,
                        o.decision.rule.as_deref().unwrap_or("default")
                    )
                )
            );
        }
    }
    println!();
    if failed == 0 {
        println!("{} {} passed", p.paint(Color::Green, "✓"), outcomes.len());
        Ok(ExitCode::SUCCESS)
    } else {
        println!(
            "{} {failed} of {} failed",
            p.paint(Color::Red, "✖"),
            outcomes.len()
        );
        Ok(ExitCode::from(1))
    }
}

pub fn policy_findings() -> Result<ExitCode> {
    let p = Painter::stdout();
    for spec in catalog() {
        println!(
            "{:<26} {}  {}",
            spec.id,
            p.paint(
                risk_color(spec.max_risk),
                &format!("{:<8}", spec.max_risk.as_str())
            ),
            spec.summary
        );
    }
    Ok(ExitCode::SUCCESS)
}

// ------------------------------------------------------------------- hook

/// Payloads larger than this are refused (the adapter answers with its
/// fail-closed error response).
const MAX_HOOK_INPUT: u64 = 16 * 1024 * 1024;

pub fn hook(policy: Option<&Path>, agent: &str) -> Result<ExitCode> {
    let adapter = adapters::adapter(agent).context("unknown adapter")?;
    let mut input = String::new();
    let read = std::io::stdin()
        .take(MAX_HOOK_INPUT + 1)
        .read_to_string(&mut input);
    let response = match read {
        Ok(n) if n as u64 > MAX_HOOK_INPUT => adapter.respond_error("hook input too large"),
        Ok(_) => adapters::run_hook(adapter.as_ref(), &input, policy),
        Err(e) => adapter.respond_error(&format!("cannot read stdin: {e}")),
    };
    if let Some(out) = &response.stdout {
        println!("{out}");
    }
    if let Some(err) = &response.stderr {
        eprintln!("{err}");
    }
    Ok(ExitCode::from(
        u8::try_from(response.exit_code).unwrap_or(1),
    ))
}
