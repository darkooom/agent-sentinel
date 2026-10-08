//! Making untrusted text safe to print in a terminal.
//!
//! Commands come from an agent, and an agent may be following injected
//! instructions. Printing a command raw lets it emit escape sequences that
//! move the cursor, clear lines or recolor text, so a confirmation prompt
//! could show `ls` while `rm -rf ~` is what runs. Bidi overrides can reorder
//! what is displayed ("Trojan Source"). Everything that is not plain
//! printable text is shown as a visible escape instead.

/// Escape control characters, bidi controls and invisible characters.
/// Newlines are kept; tabs become spaces.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => out.push('\n'),
            '\t' => out.push_str("    "),
            '\x1b' => out.push_str("\\e"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if is_invisible(c) => out.push_str(&format!("<U+{:04X}>", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// [`sanitize`] for single-line contexts: newlines become `⏎`.
pub fn sanitize_line(text: &str) -> String {
    sanitize(text).replace('\n', " ⏎ ")
}

fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0x200B..=0x200F   // zero-width space/joiners, LRM, RLM
        | 0x202A..=0x202E // bidi embeddings and overrides
        | 0x2060..=0x2064 // word joiner, invisible operators
        | 0x2066..=0x2069 // bidi isolates
        | 0xFEFF          // zero-width no-break space
        | 0x00AD          // soft hyphen
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_terminal_control_sequences() {
        let hostile = "rm -rf ~\x1b[2K\x1b[1Gls -la";
        let safe = sanitize(hostile);
        assert!(!safe.contains('\x1b'));
        assert_eq!(safe, "rm -rf ~\\e[2K\\e[1Gls -la");
        assert_eq!(sanitize("a\rb\x07"), "a\\rb\\x07");
    }

    #[test]
    fn exposes_bidi_and_zero_width() {
        assert_eq!(sanitize("ls\u{202E}fr- mr"), "ls<U+202E>fr- mr");
        assert_eq!(sanitize("r\u{200B}m"), "r<U+200B>m");
    }

    #[test]
    fn keeps_normal_text() {
        assert_eq!(
            sanitize("git push --force origin main"),
            "git push --force origin main"
        );
        assert_eq!(
            sanitize("echo 'héllo wörld' 日本"),
            "echo 'héllo wörld' 日本"
        );
        assert_eq!(sanitize_line("a\nb"), "a ⏎ b");
    }
}
