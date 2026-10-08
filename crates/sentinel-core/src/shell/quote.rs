/// Quote a string so a POSIX shell reads it back as exactly one word.
pub fn quote_word(word: &str) -> String {
    if word.is_empty() {
        return "''".to_string();
    }
    let safe = word
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,^".contains(c));
    if safe {
        return word.to_string();
    }
    let mut out = String::with_capacity(word.len() + 2);
    out.push('\'');
    for c in word.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Join argv into a command line that parses back to the same words.
pub fn quote_argv<S: AsRef<str>>(argv: &[S]) -> String {
    argv.iter()
        .map(|a| quote_word(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::parse;

    #[test]
    fn round_trips_through_the_parser() {
        let argv = [
            "rm",
            "-rf",
            "dir with space",
            "it's",
            "$HOME",
            "a;b",
            "",
            "*",
        ];
        let line = quote_argv(&argv);
        let script = parse(&line);
        let cmd = script.commands().next().unwrap();
        let words: Vec<&str> = cmd.words.iter().map(|w| w.text.as_str()).collect();
        assert_eq!(words, argv);
        assert!(cmd.words.iter().all(|w| w.is_static() && !w.glob));
    }
}
