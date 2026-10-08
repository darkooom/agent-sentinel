//! Terminal output: color, the decision panel, and the confirmation prompt.
//!
//! Color is used only for state: green allowed, yellow confirm, red
//! blocked, cyan informational. Everything that came from an agent is
//! passed through `display::sanitize` before it is printed.

use std::io::{self, IsTerminal, Write};

use sentinel_core::display::{sanitize, sanitize_line};
use sentinel_core::{secrets, Analysis, Risk};
use sentinel_policy::{Decision, Verdict};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Clone, Copy)]
pub enum Color {
    Red,
    Green,
    Yellow,
    Cyan,
    Dim,
    Bold,
    Plain,
}

#[derive(Clone, Copy)]
pub struct Painter {
    enabled: bool,
}

impl Painter {
    fn allowed() -> bool {
        std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
            && std::env::var("TERM").map_or(true, |t| t != "dumb")
            && !crate::NO_COLOR.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn stdout() -> Painter {
        Painter {
            enabled: Self::allowed() && io::stdout().is_terminal(),
        }
    }
    pub fn stderr() -> Painter {
        Painter {
            enabled: Self::allowed() && io::stderr().is_terminal(),
        }
    }
    pub fn tty() -> Painter {
        Painter {
            enabled: Self::allowed(),
        }
    }

    pub fn paint(&self, color: Color, text: &str) -> String {
        if !self.enabled {
            return text.to_string();
        }
        let code = match color {
            Color::Red => "1;31",
            Color::Green => "1;32",
            Color::Yellow => "1;33",
            Color::Cyan => "36",
            Color::Dim => "2",
            Color::Bold => "1",
            Color::Plain => return text.to_string(),
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}

pub fn verdict_color(v: Verdict) -> Color {
    match v {
        Verdict::Allow => Color::Green,
        Verdict::Confirm => Color::Yellow,
        Verdict::Deny => Color::Red,
    }
}

pub fn risk_color(r: Risk) -> Color {
    match r {
        Risk::Critical | Risk::High => Color::Red,
        Risk::Medium => Color::Yellow,
        Risk::Low => Color::Dim,
    }
}

/// `COLUMNS` if set, else the terminal size, else 80.
pub fn term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.parse().ok())
        .or_else(|| crossterm::terminal::size().ok().map(|(w, _)| w as usize))
        .unwrap_or(80)
}

/// Shorten the home directory to `~`.
pub fn tilde(path: &std::path::Path) -> String {
    sentinel_core::paths::display(path, std::env::home_dir().as_deref())
}

// ------------------------------------------------------------------ panel

struct Seg {
    text: String,
    color: Color,
}

enum Row {
    Blank,
    Text(Vec<Seg>),
    Divider,
}

/// A boxed panel with a title and right-aligned header tag.
pub struct Panel {
    width: usize,
    tag: Option<Seg>,
    rows: Vec<Row>,
}

impl Panel {
    pub fn new() -> Panel {
        Panel {
            width: term_width().clamp(44, 78),
            tag: None,
            rows: Vec::new(),
        }
    }

    fn inner(&self) -> usize {
        self.width - 6
    }

    pub fn tag(mut self, text: &str, color: Color) -> Self {
        self.tag = Some(Seg {
            text: text.into(),
            color,
        });
        self
    }

    pub fn blank(mut self) -> Self {
        self.rows.push(Row::Blank);
        self
    }

    pub fn divider(mut self) -> Self {
        self.rows.push(Row::Divider);
        self
    }

    /// A line of mixed segments; wrapped if it is too long.
    pub fn line(mut self, segs: &[(&str, Color)]) -> Self {
        let inner = self.inner();
        let mut current: Vec<Seg> = Vec::new();
        let mut used = 0;
        for (text, color) in segs {
            let mut buf = String::new();
            for ch in text.chars() {
                let w = ch.width().unwrap_or(0);
                if used + w > inner {
                    if !buf.is_empty() {
                        current.push(Seg {
                            text: std::mem::take(&mut buf),
                            color: *color,
                        });
                    }
                    self.rows.push(Row::Text(std::mem::take(&mut current)));
                    used = 0;
                    buf.push_str("  ");
                    used += 2;
                }
                buf.push(ch);
                used += w;
            }
            if !buf.is_empty() {
                current.push(Seg {
                    text: buf,
                    color: *color,
                });
            }
        }
        self.rows.push(Row::Text(current));
        self
    }

    pub fn text(self, text: &str, color: Color) -> Self {
        self.line(&[(text, color)])
    }

    /// Multi-line untrusted text (a command), sanitized, at most `max` lines.
    pub fn block(mut self, prefix: &str, text: &str, color: Color, max: usize) -> Self {
        let safe = sanitize(text);
        let lines: Vec<&str> = safe.lines().collect();
        for (i, l) in lines.iter().take(max).enumerate() {
            let p = if i == 0 { prefix } else { "  " };
            self = self.line(&[(p, Color::Dim), (l, color)]);
        }
        if lines.len() > max {
            self = self.text(&format!("  … {} more lines", lines.len() - max), Color::Dim);
        }
        self
    }

    /// A labeled value on one line; long values keep their end (`…/app`).
    pub fn field(self, label: &str, value: &str) -> Self {
        let padded = format!("{label:<9}");
        let room = self.inner().saturating_sub(padded.width());
        let value = if value.width() > room {
            let mut tail: Vec<char> = Vec::new();
            let mut used = 1;
            for c in value.chars().rev() {
                let w = c.width().unwrap_or(0);
                if used + w > room {
                    break;
                }
                tail.push(c);
                used += w;
            }
            format!("…{}", tail.into_iter().rev().collect::<String>())
        } else {
            value.to_string()
        };
        self.line(&[(&padded, Color::Dim), (&value, Color::Plain)])
    }

    pub fn render(&self, p: &Painter) -> String {
        let w = self.width;
        let border = |s: &str| p.paint(Color::Dim, s);
        let mut out = String::new();
        // ┌─ agent-sentinel ───────── high ─┐
        let title = " agent-sentinel ";
        let tag_len = self.tag.as_ref().map_or(0, |t| t.text.width() + 2);
        let fill = w.saturating_sub(2 + 1 + title.width() + tag_len + 1);
        out.push_str(&border("┌─"));
        out.push_str(&p.paint(Color::Cyan, title));
        out.push_str(&border(&"─".repeat(fill)));
        if let Some(t) = &self.tag {
            out.push(' ');
            out.push_str(&p.paint(t.color, &t.text));
            out.push(' ');
        }
        out.push_str(&border("─┐"));
        out.push('\n');
        for row in &self.rows {
            match row {
                Row::Blank => {
                    out.push_str(&border("│"));
                    out.push_str(&" ".repeat(w - 2));
                    out.push_str(&border("│"));
                }
                Row::Divider => {
                    out.push_str(&border(&format!("├{}┤", "─".repeat(w - 2))));
                }
                Row::Text(segs) => {
                    let used: usize = segs.iter().map(|s| s.text.width()).sum();
                    out.push_str(&border("│"));
                    out.push_str("  ");
                    for s in segs {
                        out.push_str(&p.paint(s.color, &s.text));
                    }
                    out.push_str(&" ".repeat((w - 4).saturating_sub(used)));
                    out.push_str(&border("│"));
                }
            }
            out.push('\n');
        }
        out.push_str(&border(&format!("└{}┘", "─".repeat(w - 2))));
        out.push('\n');
        out
    }
}

pub struct Context<'a> {
    pub target: &'a str,
    pub agent: &'a str,
    pub project: Option<&'a std::path::Path>,
    pub cwd: &'a std::path::Path,
}

/// The decision panel shared by `run` and `check`.
pub fn decision_panel(decision: &Decision, analysis: &Analysis, ctx: &Context) -> Panel {
    let (icon, label) = match decision.verdict {
        Verdict::Deny => ("✖", "BLOCKED"),
        Verdict::Confirm => ("⚠", "CONFIRMATION REQUIRED"),
        Verdict::Allow => ("✓", "ALLOWED"),
    };
    let color = verdict_color(decision.verdict);
    let mut panel = Panel::new()
        .tag(decision.risk.as_str(), risk_color(decision.risk))
        .blank()
        .line(&[(&format!("{icon} {label}"), color)])
        .blank()
        .block("$ ", &secrets::redact(ctx.target), Color::Bold, 6)
        .blank()
        .text(&sanitize_line(&decision.reason), Color::Plain);

    let mut secrets_found: Vec<String> = Vec::new();
    let mut shown = 0;
    for f in &analysis.findings {
        for d in &f.details {
            if let Some(name) = d.strip_prefix("detected: ") {
                if !secrets_found.iter().any(|s| s == name) {
                    secrets_found.push(name.to_string());
                }
            }
        }
        if f.message == decision.reason || shown >= 4 {
            continue;
        }
        panel = panel.line(&[("· ", Color::Dim), (&sanitize_line(&f.message), Color::Dim)]);
        shown += 1;
    }
    if analysis.findings.len() > shown + 1 && shown >= 4 {
        panel = panel.text(
            &format!(
                "· +{} more (sentinel check --json)",
                analysis.findings.len() - shown
            ),
            Color::Dim,
        );
    }
    panel = panel.blank();
    if !secrets_found.is_empty() {
        panel = panel.field("secrets", &sanitize_line(&secrets_found.join(", ")));
    }
    if let Some(rule) = &decision.rule {
        panel = panel.field("rule", rule);
    }
    let where_ = ctx.project.unwrap_or(ctx.cwd);
    panel = panel
        .field("project", &sanitize_line(&tilde(where_)))
        .field("agent", &sanitize_line(ctx.agent));
    panel.blank()
}

// ----------------------------------------------------------------- prompt

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Once,
    Session,
    Deny,
}

/// Why no human could be asked.
pub enum NoPrompt {
    NoTerminal,
    InsideAgent(&'static str),
}

/// An agent TUI owns the terminal: prompting there would race it for
/// keystrokes. These markers are set by the agent for child processes.
pub fn inside_agent() -> Option<&'static str> {
    let set = |v: &str| std::env::var_os(v).is_some_and(|x| !x.is_empty());
    if set("CLAUDECODE") {
        Some("Claude Code")
    } else if set("AI_AGENT") {
        Some("an AI agent")
    } else {
        None
    }
}

/// Show the confirmation panel on the controlling terminal and read one
/// key from it. Stdin is never used: an agent that pipes `a` into
/// sentinel must not be able to approve its own request.
pub fn confirm(panel: Panel) -> Result<Answer, NoPrompt> {
    if let Some(agent) = inside_agent() {
        return Err(NoPrompt::InsideAgent(agent));
    }
    let mut tty = open_tty().ok_or(NoPrompt::NoTerminal)?;
    let p = Painter::tty();
    let panel = panel.divider().line(&[
        ("[a]", Color::Bold),
        (" allow once   ", Color::Plain),
        ("[s]", Color::Bold),
        (" allow for session   ", Color::Plain),
        ("[d]", Color::Bold),
        (" deny", Color::Plain),
    ]);
    let _ = write!(tty, "\n{}", panel.render(&p));
    let _ = write!(tty, "  {} ", p.paint(Color::Yellow, "›"));
    let _ = tty.flush();
    let answer = read_key().ok_or(NoPrompt::NoTerminal)?;
    let (text, color) = match answer {
        Answer::Once => ("allowed once", Color::Green),
        Answer::Session => ("allowed for this session", Color::Green),
        Answer::Deny => ("denied", Color::Red),
    };
    let _ = writeln!(tty, "{}\n", p.paint(color, text));
    Ok(answer)
}

#[cfg(unix)]
fn open_tty() -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()
}

#[cfg(not(unix))]
fn open_tty() -> Option<std::fs::File> {
    if io::stdin().is_terminal() && io::stderr().is_terminal() {
        std::fs::OpenOptions::new().write(true).open("CONOUT$").ok()
    } else {
        None
    }
}

struct RawMode;

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// One keypress from the terminal. Anything but a/s/y is a denial.
fn read_key() -> Option<Answer> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    crossterm::terminal::enable_raw_mode().ok()?;
    let _guard = RawMode;
    // Drop keys typed before the prompt appeared.
    while event::poll(std::time::Duration::from_millis(0)).unwrap_or(false) {
        let _ = event::read();
    }
    loop {
        let Event::Key(key) = event::read().ok()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return Some(Answer::Deny);
        }
        return Some(match key.code {
            KeyCode::Char('a' | 'A' | 'y' | 'Y') => Answer::Once,
            KeyCode::Char('s' | 'S') => Answer::Session,
            _ => Answer::Deny,
        });
    }
}

/// Write a panel to stderr.
pub fn eprint_panel(panel: &Panel) {
    let p = Painter::stderr();
    let mut err = io::stderr().lock();
    let _ = write!(err, "{}", panel.render(&p));
}
