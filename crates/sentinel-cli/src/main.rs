//! `sentinel`: the firewall for AI coding agents.

mod commands;
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use clap::{Parser, Subcommand};

pub static NO_COLOR: AtomicBool = AtomicBool::new(false);

/// Exit code of `sentinel run` when an action is not allowed.
pub const EXIT_BLOCKED: u8 = 126;

#[derive(Parser)]
#[command(
    name = "sentinel",
    version,
    about = "The firewall for AI coding agents",
    long_about = "Inspects what AI coding agents are about to do (shell commands, file access, \
                  network requests) and allows, denies, or asks you first, according to a policy.",
    after_help = "Start with `sentinel init`, then try `sentinel run \"rm -rf ./test\"`.\nDocs: https://github.com/darkooom/agent-sentinel"
)]
struct Cli {
    /// Use this policy file instead of discovering .sentinel/policy.yml
    #[arg(long, global = true, value_name = "FILE")]
    policy: Option<PathBuf>,

    /// Disable colored output (also honors NO_COLOR)
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create .sentinel/policy.yml in the current directory
    Init {
        /// Overwrite an existing policy
        #[arg(long)]
        force: bool,
        /// Also register the Claude Code PreToolUse hook (.claude/settings.local.json)
        #[arg(long)]
        claude_code: bool,
    },

    /// Check a command against the policy, then run it
    #[command(
        after_help = "One argument is run as a shell command line (bash -c); several arguments are executed directly.\n\n  sentinel run \"npm test && npm run lint\"\n  sentinel run cargo test --workspace\n\nExits 126 when the command is blocked; otherwise with the command's exit code."
    )]
    Run {
        /// Agent name recorded in the audit log
        #[arg(long, default_value = "cli")]
        agent: String,
        /// The command to run
        #[arg(
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },

    /// Evaluate an action without running it
    #[command(after_help = "Exit codes: 0 allow, 1 deny (or error), 3 confirm.")]
    Check {
        /// Print the full evaluation as JSON
        #[arg(long)]
        json: bool,
        /// Check reading this file instead of a command
        #[arg(long, value_name = "PATH", conflicts_with_all = ["write", "fetch"])]
        read: Option<String>,
        /// Check writing this file
        #[arg(long, value_name = "PATH", conflicts_with = "fetch")]
        write: Option<String>,
        /// Check fetching this URL
        #[arg(long, value_name = "URL")]
        fetch: Option<String>,
        /// Agent name recorded in the audit log
        #[arg(long, default_value = "cli")]
        agent: String,
        /// Command line to check
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },

    /// Show the audit log
    Log {
        /// Only today's events
        #[arg(long)]
        today: bool,
        /// Only actions that were blocked or declined
        #[arg(long)]
        denied: bool,
        /// Only events from this agent
        #[arg(long)]
        agent: Option<String>,
        /// Print raw JSON lines
        #[arg(long)]
        json: bool,
        /// Number of most recent events to show
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: usize,
        /// Show every matching event
        #[arg(long, conflicts_with = "limit")]
        all: bool,
    },

    /// Show the active policy, integrations and today's activity
    Status,

    /// Inspect and test policies
    Policy {
        #[command(subcommand)]
        action: Option<PolicyCommand>,
    },

    /// Answer a pre-execution hook from an AI agent (JSON on stdin)
    #[command(
        after_help = "Adapters:\n  claude-code  Claude Code PreToolUse hook (installed by `sentinel init --claude-code`)\n  codex        OpenAI Codex CLI PreToolUse hook\n  generic      JSON protocol for other harnesses (see docs/integrations.md)"
    )]
    Hook {
        /// Adapter for the agent's hook protocol
        #[arg(value_parser = clap::builder::PossibleValuesParser::new(sentinel_runtime::adapters::ADAPTERS))]
        agent: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Print the effective policy file
    Show,
    /// Print which policy applies here
    Path,
    /// Check a policy file for errors
    Validate {
        /// Policy file (default: the effective policy)
        file: Option<PathBuf>,
    },
    /// Run the `tests:` section of the policy
    Test,
    /// List every finding id detectors can report
    Findings,
}

/// Rust ignores SIGPIPE, so writing to a closed pipe (`sentinel log | head`)
/// becomes a panic. Restore the default: exit quietly like other Unix tools.
#[cfg(unix)]
#[allow(unsafe_code)]
fn restore_sigpipe() {
    // SAFETY: called first thing in main, before any other threads exist;
    // only resets a signal disposition to its default.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn main() -> ExitCode {
    #[cfg(unix)]
    restore_sigpipe();
    let cli = Cli::parse();
    if cli.no_color {
        NO_COLOR.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let policy = cli.policy.as_deref();
    let result = match cli.command {
        Command::Init { force, claude_code } => commands::init(force, claude_code),
        Command::Run { agent, command } => commands::run(policy, &agent, &command),
        Command::Check {
            json,
            read,
            write,
            fetch,
            agent,
            command,
        } => commands::check(policy, &agent, json, read, write, fetch, &command),
        Command::Log {
            today,
            denied,
            agent,
            json,
            limit,
            all,
        } => commands::log(
            today,
            denied,
            agent,
            json,
            if all { None } else { Some(limit) },
        ),
        Command::Status => commands::status(policy),
        Command::Policy { action } => match action.unwrap_or(PolicyCommand::Path) {
            PolicyCommand::Show => commands::policy_show(policy),
            PolicyCommand::Path => commands::policy_path(policy),
            PolicyCommand::Validate { file } => {
                commands::policy_validate(file.as_deref().or(policy))
            }
            PolicyCommand::Test => commands::policy_test(policy),
            PolicyCommand::Findings => commands::policy_findings(),
        },
        Command::Hook { agent } => commands::hook(policy, &agent),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            let p = ui::Painter::stderr();
            eprintln!("{} {e:#}", p.paint(ui::Color::Red, "error:"));
            ExitCode::from(1)
        }
    }
}
