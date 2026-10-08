//! A conservative tokenizer for POSIX/bash command lines.
//!
//! This is not a shell. It recovers the structure that matters for policy
//! decisions: simple commands and their words after quote removal, pipelines,
//! redirections, and nested command text (`$(…)`, backticks, `<(…)`,
//! heredocs). Every simple command found anywhere in the input, including
//! inside substitutions and control structures, is returned flat, so a
//! command cannot hide behind `false &&`, `if`, or a subshell.
//!
//! Anything that cannot be resolved statically is recorded, either on the
//! word (`vars`, `substitution`, `brace`) or as an [`Issue`], so the analyzer
//! can treat it as suspicious instead of harmless.

mod quote;

pub use quote::{quote_argv, quote_word};

/// Maximum nesting of substitutions and nested shell strings.
pub const MAX_DEPTH: usize = 12;

/// One shell word after quote removal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Word {
    /// Text after quote removal. Expansions are kept in source form
    /// (`$HOME`, `${x}`, `$(…)`), so the text is only exact when
    /// [`Word::is_static`] holds.
    pub text: String,
    /// Some part of the word was quoted or escaped.
    pub quoted: bool,
    /// Parameters referenced (`$HOME` → `HOME`).
    pub vars: Vec<String>,
    /// Contains command, process or arithmetic substitution.
    pub substitution: bool,
    /// Contains unquoted brace expansion (`{a,b}`, `{1..3}`).
    pub brace: bool,
    /// Contains unquoted glob characters.
    pub glob: bool,
    /// Starts with an unquoted `~`.
    pub tilde: bool,
    /// Contains a parameter expansion outside double quotes, so its value is
    /// split into several words by the shell.
    pub split: bool,
}

impl Word {
    pub fn literal(text: impl Into<String>) -> Self {
        Word {
            text: text.into(),
            ..Word::default()
        }
    }

    /// True when the shell produces exactly `self.text` (apart from tilde
    /// and glob expansion) for this word.
    pub fn is_static(&self) -> bool {
        self.vars.is_empty() && !self.substitution && !self.brace
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectKind {
    /// `<`
    Read,
    /// `>`, `>|`, `&>`
    Write,
    /// `>>`, `&>>`
    Append,
    /// `<>`
    ReadWrite,
    /// `>&2`, `<&0`
    Dup,
    /// `<<`, `<<-`
    Heredoc,
    /// `<<<`
    HereString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub kind: RedirectKind,
    pub fd: Option<u32>,
    /// File name, heredoc delimiter, or here-string word.
    pub target: Word,
    /// Heredoc body.
    pub body: Option<String>,
    slot: Option<usize>,
}

/// A simple command: assignments, words and redirections.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimpleCommand {
    pub assignments: Vec<(String, Word)>,
    pub words: Vec<Word>,
    pub redirects: Vec<Redirect>,
    /// Standard input comes from a pipe.
    pub stdin_piped: bool,
}

/// Commands connected with `|`. Standalone commands are pipelines of one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pipeline {
    pub commands: Vec<SimpleCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    UnterminatedQuote,
    UnterminatedSubstitution,
    UnbalancedParens,
    UnsupportedSyntax(&'static str),
    TooDeep,
}

impl Issue {
    pub fn describe(&self) -> String {
        match self {
            Issue::UnterminatedQuote => "unterminated quote".into(),
            Issue::UnterminatedSubstitution => "unterminated command substitution".into(),
            Issue::UnbalancedParens => "unbalanced parentheses".into(),
            Issue::UnsupportedSyntax(what) => format!("unsupported shell syntax `{what}`"),
            Issue::TooDeep => "nesting too deep to analyze".into(),
        }
    }
}

/// Parsed command line. Nested commands (substitutions, heredoc bodies with
/// expansions) appear as additional pipelines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Script {
    pub pipelines: Vec<Pipeline>,
    pub issues: Vec<Issue>,
}

impl Script {
    pub fn commands(&self) -> impl Iterator<Item = &SimpleCommand> {
        self.pipelines.iter().flat_map(|p| p.commands.iter())
    }
}

/// Parse a command line.
pub fn parse(input: &str) -> Script {
    parse_at_depth(input, 0)
}

/// Parse nested command text (e.g. the argument of `bash -c`) that sits
/// `depth` levels below the top-level command line.
pub fn parse_at_depth(input: &str, depth: usize) -> Script {
    let mut parser = Parser::new(input, depth);
    if depth > MAX_DEPTH {
        parser.issues.push(Issue::TooDeep);
        return parser.finish();
    }
    parser.parse_list(false);
    parser.finish()
}

struct PendingHeredoc {
    slot: usize,
    delimiter: String,
    strip_tabs: bool,
    expand: bool,
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
    pipelines: Vec<Pipeline>,
    issues: Vec<Issue>,
    pending_heredocs: Vec<PendingHeredoc>,
    heredoc_bodies: Vec<Option<String>>,
}

/// A word under construction.
#[derive(Default)]
struct WordBuf {
    word: Word,
    /// Bytes at the start of `text` that were plain unquoted characters.
    /// Used to recognize `NAME=value` assignments.
    plain_prefix: usize,
    prefix_closed: bool,
}

impl WordBuf {
    fn push_plain(&mut self, c: char) {
        self.word.text.push(c);
        if !self.prefix_closed {
            self.plain_prefix += c.len_utf8();
        }
    }

    fn push_quoted(&mut self, c: char) {
        self.word.text.push(c);
        self.word.quoted = true;
        self.prefix_closed = true;
    }

    fn push_expansion(&mut self, source: &str) {
        self.word.text.push_str(source);
        self.prefix_closed = true;
    }

    fn is_empty(&self) -> bool {
        self.word.text.is_empty() && !self.word.quoted && self.word.is_static()
    }
}

#[derive(Default)]
struct Builder {
    assignments: Vec<(String, Word)>,
    words: Vec<Word>,
    redirects: Vec<Redirect>,
}

impl Builder {
    fn is_empty(&self) -> bool {
        self.assignments.is_empty() && self.words.is_empty() && self.redirects.is_empty()
    }

    fn push(&mut self, buf: WordBuf) {
        if buf.is_empty() {
            return;
        }
        if self.words.is_empty() {
            if let Some(assignment) = split_assignment(&buf) {
                self.assignments.push(assignment);
                return;
            }
        }
        self.words.push(buf.word);
    }
}

fn split_assignment(buf: &WordBuf) -> Option<(String, Word)> {
    let text = &buf.word.text;
    let eq = text.find('=')?;
    if eq == 0 || eq >= buf.plain_prefix {
        return None;
    }
    let name = text[..eq].trim_end_matches('+');
    let base = name.split('[').next().unwrap_or(name);
    let mut chars = base.chars();
    let valid = matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric());
    if !valid {
        return None;
    }
    let mut value = buf.word.clone();
    value.text = text[eq + 1..].to_string();
    value.tilde = value.text.starts_with('~');
    Some((base.to_string(), value))
}

/// Strip leading reserved words so `if rm …`, `then rm …`, `! rm …` and
/// `{ rm …; }` all expose `rm` as the command.
fn finish(builder: Builder, issues: &mut Vec<Issue>, stdin_piped: bool) -> Option<SimpleCommand> {
    let Builder {
        assignments,
        mut words,
        redirects,
    } = builder;
    while let Some(first) = words.first() {
        if first.quoted || !first.is_static() {
            break;
        }
        match first.text.as_str() {
            "!" | "{" | "}" | "then" | "else" | "elif" | "do" | "if" | "while" | "until"
            | "done" | "fi" | "esac" | "coproc" => {
                words.remove(0);
            }
            "time" => {
                words.remove(0);
                if words.first().is_some_and(|w| w.text == "-p") {
                    words.remove(0);
                }
            }
            // Loop and function headers are not commands; their bodies follow
            // as separate commands. Substitutions inside the header were
            // already collected.
            "for" | "select" | "function" => {
                words.clear();
            }
            "case" => {
                issues.push(Issue::UnsupportedSyntax("case"));
                words.clear();
            }
            _ => break,
        }
    }
    if words.is_empty() && assignments.is_empty() && redirects.is_empty() {
        return None;
    }
    Some(SimpleCommand {
        assignments,
        words,
        redirects,
        stdin_piped,
    })
}

impl Parser {
    fn new(input: &str, depth: usize) -> Self {
        Parser {
            chars: input.chars().collect(),
            pos: 0,
            depth,
            pipelines: Vec::new(),
            issues: Vec::new(),
            pending_heredocs: Vec::new(),
            heredoc_bodies: Vec::new(),
        }
    }

    fn finish(mut self) -> Script {
        if !self.pending_heredocs.is_empty() {
            self.read_heredocs();
        }
        let bodies = std::mem::take(&mut self.heredoc_bodies);
        for pipeline in &mut self.pipelines {
            for cmd in &mut pipeline.commands {
                for redirect in &mut cmd.redirects {
                    if let Some(slot) = redirect.slot.take() {
                        redirect.body = bodies.get(slot).cloned().flatten();
                    }
                }
            }
        }
        self.issues.dedup();
        Script {
            pipelines: self.pipelines,
            issues: self.issues,
        }
    }

    fn absorb(&mut self, script: Script) {
        self.pipelines.extend(script.pipelines);
        self.issues.extend(script.issues);
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn skip_blanks(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\r') => self.pos += 1,
                Some('\\') if self.peek_at(1) == Some('\n') => self.pos += 2,
                _ => break,
            }
        }
    }

    fn peek_after_blanks(&self) -> Option<char> {
        self.chars[self.pos..]
            .iter()
            .copied()
            .find(|c| !matches!(c, ' ' | '\t'))
    }

    fn skip_comment(&mut self) {
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            self.pos += 1;
        }
    }

    fn end_pipeline(
        &mut self,
        pipeline: &mut Vec<SimpleCommand>,
        cur: &mut Builder,
        piped: &mut bool,
    ) {
        self.pipe(pipeline, cur, piped);
        *piped = false;
        if !pipeline.is_empty() {
            self.pipelines.push(Pipeline {
                commands: std::mem::take(pipeline),
            });
        }
    }

    /// Complete the current command and keep the pipeline open.
    fn pipe(&mut self, pipeline: &mut Vec<SimpleCommand>, cur: &mut Builder, piped: &mut bool) {
        if let Some(cmd) = finish(std::mem::take(cur), &mut self.issues, *piped) {
            pipeline.push(cmd);
            *piped = false;
        }
    }

    /// Parse a command list until end of input, or until the `)` closing a
    /// `$(`/`<(` substitution when `in_substitution` is set.
    fn parse_list(&mut self, in_substitution: bool) {
        let mut pipeline = Vec::new();
        let mut cur = Builder::default();
        let mut piped = false;
        let mut parens = 0usize;
        loop {
            self.skip_blanks();
            let Some(c) = self.peek() else {
                if in_substitution {
                    self.issues.push(Issue::UnterminatedSubstitution);
                }
                if parens > 0 {
                    self.issues.push(Issue::UnbalancedParens);
                }
                break;
            };
            match c {
                '#' => self.skip_comment(),
                '\n' => {
                    self.pos += 1;
                    self.end_pipeline(&mut pipeline, &mut cur, &mut piped);
                    if !self.pending_heredocs.is_empty() {
                        self.read_heredocs();
                    }
                }
                ';' => {
                    self.pos += 1;
                    // `;;`, `;&`, `;;&` only appear in `case`, which is flagged.
                    while matches!(self.peek(), Some(';' | '&')) {
                        self.pos += 1;
                    }
                    self.end_pipeline(&mut pipeline, &mut cur, &mut piped);
                }
                '&' => {
                    self.pos += 1;
                    if self.eat('&') {
                        self.end_pipeline(&mut pipeline, &mut cur, &mut piped);
                    } else if self.eat('>') {
                        let kind = if self.eat('>') {
                            RedirectKind::Append
                        } else {
                            RedirectKind::Write
                        };
                        self.redirect_target(&mut cur, kind, None);
                    } else {
                        self.end_pipeline(&mut pipeline, &mut cur, &mut piped);
                    }
                }
                '|' => {
                    self.pos += 1;
                    if self.eat('|') {
                        self.end_pipeline(&mut pipeline, &mut cur, &mut piped);
                    } else {
                        self.eat('&');
                        self.pipe(&mut pipeline, &mut cur, &mut piped);
                        piped = true;
                    }
                }
                '(' => {
                    self.pos += 1;
                    if cur.is_empty() && self.peek() == Some('(') {
                        // Arithmetic command `(( … ))`.
                        self.pos += 1;
                        let inner = self.read_until_double_paren();
                        self.scan_expansions(&inner);
                    } else if cur.words.len() == 1
                        && cur.assignments.is_empty()
                        && self.peek_after_blanks() == Some(')')
                    {
                        // Function definition `name ()`: drop the name, the
                        // body follows as ordinary commands.
                        self.skip_blanks();
                        self.pos += 1;
                        cur = Builder::default();
                    } else if cur.words.is_empty()
                        && self.chars.get(self.pos.wrapping_sub(2)) == Some(&'=')
                        && !cur.assignments.is_empty()
                    {
                        // Array assignment `a=( … )`.
                        let inner = self.read_balanced_parens();
                        self.scan_expansions(&inner);
                        if let Some((_, value)) = cur.assignments.last_mut() {
                            value.text = format!("({inner})");
                        }
                    } else {
                        if !cur.is_empty() {
                            self.issues.push(Issue::UnbalancedParens);
                            self.end_pipeline(&mut pipeline, &mut cur, &mut piped);
                        }
                        parens += 1;
                    }
                }
                ')' => {
                    self.pos += 1;
                    if parens > 0 {
                        parens -= 1;
                        self.end_pipeline(&mut pipeline, &mut cur, &mut piped);
                    } else if in_substitution {
                        self.end_pipeline(&mut pipeline, &mut cur, &mut piped);
                        return;
                    } else {
                        self.issues.push(Issue::UnbalancedParens);
                        self.end_pipeline(&mut pipeline, &mut cur, &mut piped);
                    }
                }
                '<' | '>' if self.peek_at(1) != Some('(') => self.redirect(&mut cur, None),
                _ => {
                    let start = self.pos;
                    let buf = self.lex_word();
                    if self.pos == start {
                        // Defensive: never loop without progress.
                        self.pos += 1;
                        continue;
                    }
                    let is_fd = !buf.word.quoted
                        && !buf.word.text.is_empty()
                        && buf.word.text.len() <= 4
                        && buf.word.text.chars().all(|c| c.is_ascii_digit());
                    if is_fd
                        && matches!(self.peek(), Some('<' | '>'))
                        && self.peek_at(1) != Some('(')
                    {
                        let fd = buf.word.text.parse().ok();
                        self.redirect(&mut cur, fd);
                    } else {
                        cur.push(buf);
                    }
                }
            }
        }
        self.end_pipeline(&mut pipeline, &mut cur, &mut piped);
    }

    fn redirect(&mut self, cur: &mut Builder, fd: Option<u32>) {
        let Some(op) = self.bump() else { return };
        let kind = if op == '<' {
            if self.eat('<') {
                if self.eat('<') {
                    RedirectKind::HereString
                } else {
                    let strip_tabs = self.eat('-');
                    self.heredoc(cur, fd, strip_tabs);
                    return;
                }
            } else if self.eat('>') {
                RedirectKind::ReadWrite
            } else if self.eat('&') {
                RedirectKind::Dup
            } else {
                RedirectKind::Read
            }
        } else if self.eat('>') {
            RedirectKind::Append
        } else if self.eat('|') {
            RedirectKind::Write
        } else if self.eat('&') {
            // `>&2` duplicates a descriptor; `>&file` writes stdout+stderr.
            self.skip_blanks();
            let target = self.lex_word().word;
            let dup = target.text == "-" || target.text.chars().all(|c| c.is_ascii_digit());
            cur.redirects.push(Redirect {
                kind: if dup {
                    RedirectKind::Dup
                } else {
                    RedirectKind::Write
                },
                fd,
                target,
                body: None,
                slot: None,
            });
            return;
        } else {
            RedirectKind::Write
        };
        self.redirect_target(cur, kind, fd);
    }

    fn redirect_target(&mut self, cur: &mut Builder, kind: RedirectKind, fd: Option<u32>) {
        self.skip_blanks();
        let target = self.lex_word().word;
        cur.redirects.push(Redirect {
            kind,
            fd,
            target,
            body: None,
            slot: None,
        });
    }

    fn heredoc(&mut self, cur: &mut Builder, fd: Option<u32>, strip_tabs: bool) {
        self.skip_blanks();
        let delimiter = self.lex_word().word;
        let slot = self.heredoc_bodies.len();
        self.heredoc_bodies.push(None);
        self.pending_heredocs.push(PendingHeredoc {
            slot,
            delimiter: delimiter.text.clone(),
            strip_tabs,
            expand: !delimiter.quoted,
        });
        cur.redirects.push(Redirect {
            kind: RedirectKind::Heredoc,
            fd,
            target: delimiter,
            body: None,
            slot: Some(slot),
        });
    }

    fn read_heredocs(&mut self) {
        for heredoc in std::mem::take(&mut self.pending_heredocs) {
            let mut body = String::new();
            while self.pos < self.chars.len() {
                let mut line = String::new();
                while let Some(c) = self.bump() {
                    if c == '\n' {
                        break;
                    }
                    line.push(c);
                }
                let line = if heredoc.strip_tabs {
                    line.trim_start_matches('\t').to_string()
                } else {
                    line
                };
                if line == heredoc.delimiter {
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            if heredoc.expand {
                self.scan_expansions(&body);
            }
            self.heredoc_bodies[heredoc.slot] = Some(body);
        }
    }

    fn lex_word(&mut self) -> WordBuf {
        let mut buf = WordBuf::default();
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | '(' | ')' => break,
                '<' | '>' => {
                    if self.peek_at(1) != Some('(') {
                        break;
                    }
                    // Process substitution `<( … )` / `>( … )`.
                    self.pos += 2;
                    self.nested_list();
                    buf.push_expansion(if c == '<' { "<(…)" } else { ">(…)" });
                    buf.word.substitution = true;
                }
                '\\' => {
                    self.pos += 1;
                    match self.bump() {
                        Some('\n') => {}
                        Some(escaped) => buf.push_quoted(escaped),
                        None => buf.push_plain('\\'),
                    }
                }
                '\'' => {
                    self.pos += 1;
                    self.lex_single_quoted(&mut buf);
                }
                '"' => {
                    self.pos += 1;
                    self.lex_double_quoted(&mut buf);
                }
                '$' => self.lex_dollar(&mut buf, false),
                '`' => self.lex_backtick(&mut buf),
                '*' | '?' | '[' => {
                    self.pos += 1;
                    buf.word.glob = true;
                    buf.push_plain(c);
                }
                '{' => {
                    if self.looks_like_brace_expansion() {
                        buf.word.brace = true;
                    }
                    self.pos += 1;
                    buf.push_plain(c);
                }
                '~' if buf.word.text.is_empty() && !buf.word.quoted => {
                    self.pos += 1;
                    buf.word.tilde = true;
                    buf.push_plain(c);
                }
                _ => {
                    self.pos += 1;
                    buf.push_plain(c);
                }
            }
        }
        buf
    }

    fn lex_single_quoted(&mut self, buf: &mut WordBuf) {
        buf.word.quoted = true;
        buf.prefix_closed = true;
        loop {
            match self.bump() {
                None => {
                    self.issues.push(Issue::UnterminatedQuote);
                    return;
                }
                Some('\'') => return,
                Some(c) => buf.push_quoted(c),
            }
        }
    }

    fn lex_double_quoted(&mut self, buf: &mut WordBuf) {
        buf.word.quoted = true;
        buf.prefix_closed = true;
        loop {
            match self.peek() {
                None => {
                    self.issues.push(Issue::UnterminatedQuote);
                    return;
                }
                Some('"') => {
                    self.pos += 1;
                    return;
                }
                Some('\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(c @ ('$' | '`' | '"' | '\\')) => {
                            self.pos += 1;
                            buf.push_quoted(c);
                        }
                        Some('\n') => self.pos += 1,
                        _ => buf.push_quoted('\\'),
                    }
                }
                Some('$') => self.lex_dollar(buf, true),
                Some('`') => self.lex_backtick(buf),
                Some(c) => {
                    self.pos += 1;
                    buf.push_quoted(c);
                }
            }
        }
    }

    /// `$'…'` with C escapes. Decoded so `$'\x72\x6d'` is seen as `rm`.
    fn lex_ansi_c(&mut self, buf: &mut WordBuf) {
        buf.word.quoted = true;
        buf.prefix_closed = true;
        loop {
            match self.bump() {
                None => {
                    self.issues.push(Issue::UnterminatedQuote);
                    return;
                }
                Some('\'') => return,
                Some('\\') => {
                    let Some(e) = self.bump() else {
                        buf.push_quoted('\\');
                        continue;
                    };
                    let decoded = match e {
                        'n' => Some('\n'),
                        't' => Some('\t'),
                        'r' => Some('\r'),
                        'a' => Some('\x07'),
                        'b' => Some('\x08'),
                        'e' | 'E' => Some('\x1b'),
                        'f' => Some('\x0c'),
                        'v' => Some('\x0b'),
                        '\\' | '\'' | '"' | '?' => Some(e),
                        'x' => self.read_radix(16, 2),
                        'u' => self.read_radix(16, 4),
                        'U' => self.read_radix(16, 8),
                        '0'..='7' => {
                            self.pos -= 1;
                            self.read_radix(8, 3)
                        }
                        'c' => self
                            .bump()
                            .map(|c| char::from((c.to_ascii_uppercase() as u8) & 0x1f)),
                        other => {
                            buf.push_quoted('\\');
                            Some(other)
                        }
                    };
                    if let Some(c) = decoded {
                        buf.push_quoted(c);
                    }
                }
                Some(c) => buf.push_quoted(c),
            }
        }
    }

    fn read_radix(&mut self, radix: u32, max: usize) -> Option<char> {
        let mut value: u32 = 0;
        let mut digits = 0;
        while digits < max {
            match self.peek().and_then(|c| c.to_digit(radix)) {
                Some(d) => {
                    value = value.saturating_mul(radix).saturating_add(d);
                    self.pos += 1;
                    digits += 1;
                }
                None => break,
            }
        }
        if digits == 0 {
            return None;
        }
        char::from_u32(value)
    }

    fn lex_dollar(&mut self, buf: &mut WordBuf, in_double_quotes: bool) {
        self.pos += 1; // `$`
        match self.peek() {
            Some('(') => {
                self.pos += 1;
                if self.eat('(') {
                    let inner = self.read_until_double_paren();
                    self.scan_expansions(&inner);
                    buf.push_expansion("$((…))");
                } else {
                    self.nested_list();
                    buf.push_expansion("$(…)");
                }
                buf.word.substitution = true;
            }
            Some('{') => {
                self.pos += 1;
                let inner = self.read_braced();
                let name: String = inner
                    .trim_start_matches(['!', '#'])
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if inner.contains('$') || inner.contains('`') {
                    self.scan_expansions(&inner);
                    if inner.contains("$(") || inner.contains('`') {
                        buf.word.substitution = true;
                    }
                }
                // Indirect (`${!x}`) and operator forms are still variable
                // references; the name is best effort.
                buf.word
                    .vars
                    .push(if name.is_empty() { inner.clone() } else { name });
                buf.word.split |= !in_double_quotes;
                buf.push_expansion(&format!("${{{inner}}}"));
            }
            Some('\'') if !in_double_quotes => {
                self.pos += 1;
                self.lex_ansi_c(buf);
            }
            Some('"') if !in_double_quotes => {
                self.pos += 1;
                self.lex_double_quoted(buf);
            }
            Some(c) if c == '_' || c.is_ascii_alphabetic() => {
                let mut name = String::new();
                while let Some(c) = self.peek() {
                    if c == '_' || c.is_ascii_alphanumeric() {
                        name.push(c);
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                buf.push_expansion(&format!("${name}"));
                buf.word.vars.push(name);
                buf.word.split |= !in_double_quotes;
            }
            Some(c) if c.is_ascii_digit() || "@*#?$!-".contains(c) => {
                self.pos += 1;
                buf.push_expansion(&format!("${c}"));
                buf.word.vars.push(c.to_string());
                buf.word.split |= !in_double_quotes;
            }
            _ => {
                if in_double_quotes {
                    buf.push_quoted('$');
                } else {
                    buf.push_plain('$');
                }
            }
        }
    }

    fn lex_backtick(&mut self, buf: &mut WordBuf) {
        self.pos += 1;
        let mut inner = String::new();
        loop {
            match self.bump() {
                None => {
                    self.issues.push(Issue::UnterminatedSubstitution);
                    break;
                }
                Some('`') => break,
                Some('\\') => match self.peek() {
                    Some(c @ ('`' | '\\' | '$')) => {
                        self.pos += 1;
                        inner.push(c);
                    }
                    _ => inner.push('\\'),
                },
                Some(c) => inner.push(c),
            }
        }
        let script = parse_at_depth(&inner, self.depth + 1);
        self.absorb(script);
        buf.push_expansion("`…`");
        buf.word.substitution = true;
    }

    /// Parse `$( … )` / `<( … )` in place, consuming the closing paren.
    fn nested_list(&mut self) {
        if self.depth >= MAX_DEPTH {
            self.issues.push(Issue::TooDeep);
            self.read_balanced_parens();
            return;
        }
        self.depth += 1;
        self.parse_list(true);
        self.depth -= 1;
    }

    /// Find `$(…)` and backticks in text that undergoes expansion but is not
    /// itself a command (heredoc bodies, `${…}` operands, arithmetic).
    fn scan_expansions(&mut self, text: &str) {
        if !text.contains('$') && !text.contains('`') {
            return;
        }
        if self.depth >= MAX_DEPTH {
            self.issues.push(Issue::TooDeep);
            return;
        }
        let mut sub = Parser::new(text, self.depth + 1);
        let mut scratch = WordBuf::default();
        while let Some(c) = sub.peek() {
            match c {
                '\\' => sub.pos += 2,
                '$' => sub.lex_dollar(&mut scratch, true),
                '`' => sub.lex_backtick(&mut scratch),
                _ => sub.pos += 1,
            }
        }
        let script = sub.finish();
        self.absorb(script);
    }

    /// Read up to the matching `)`, honoring quotes and nesting. Used when a
    /// construct is skipped rather than parsed.
    fn read_balanced_parens(&mut self) -> String {
        let mut depth = 0usize;
        let mut out = String::new();
        while let Some(c) = self.bump() {
            match c {
                '\\' => {
                    out.push(c);
                    if let Some(n) = self.bump() {
                        out.push(n);
                    }
                }
                '\'' | '"' => {
                    out.push(c);
                    while let Some(q) = self.bump() {
                        out.push(q);
                        if q == c {
                            break;
                        }
                    }
                }
                '(' => {
                    depth += 1;
                    out.push(c);
                }
                ')' => {
                    if depth == 0 {
                        return out;
                    }
                    depth -= 1;
                    out.push(c);
                }
                _ => out.push(c),
            }
        }
        self.issues.push(Issue::UnterminatedSubstitution);
        out
    }

    fn read_until_double_paren(&mut self) -> String {
        let mut depth = 0usize;
        let mut out = String::new();
        while let Some(c) = self.bump() {
            match c {
                '(' => depth += 1,
                ')' if depth == 0 && self.peek() == Some(')') => {
                    self.pos += 1;
                    return out;
                }
                ')' => depth = depth.saturating_sub(1),
                _ => {}
            }
            out.push(c);
        }
        self.issues.push(Issue::UnterminatedSubstitution);
        out
    }

    fn read_braced(&mut self) -> String {
        let mut depth = 0usize;
        let mut out = String::new();
        while let Some(c) = self.bump() {
            match c {
                '\\' => {
                    out.push(c);
                    if let Some(n) = self.bump() {
                        out.push(n);
                    }
                }
                '\'' | '"' => {
                    out.push(c);
                    while let Some(q) = self.bump() {
                        out.push(q);
                        if q == c {
                            break;
                        }
                    }
                }
                '{' => {
                    depth += 1;
                    out.push(c);
                }
                '}' => {
                    if depth == 0 {
                        return out;
                    }
                    depth -= 1;
                    out.push(c);
                }
                _ => out.push(c),
            }
        }
        self.issues.push(Issue::UnterminatedSubstitution);
        out
    }

    /// `{a,b}` or `{1..3}` within the current unquoted word.
    fn looks_like_brace_expansion(&self) -> bool {
        let mut depth = 0usize;
        let mut has_comma = false;
        let mut prev = '\0';
        let mut has_range = false;
        for &c in &self.chars[self.pos..] {
            match c {
                ' ' | '\t' | '\n' | ';' | '&' | '|' | '<' | '>' | '(' | ')' | '\'' | '"' => {
                    return false
                }
                '{' => depth += 1,
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return has_comma || has_range;
                    }
                }
                ',' if depth == 1 => has_comma = true,
                '.' if depth == 1 && prev == '.' => has_range = true,
                _ => {}
            }
            prev = c;
        }
        false
    }
}

#[cfg(test)]
mod tests;
