use super::*;

fn exes(cmd: &str) -> Vec<String> {
    extract(cmd, Path::new("/work"), Some(Path::new("/home/dev")))
        .invocations
        .iter()
        .map(|i| i.exe.clone())
        .collect()
}

fn find<'a>(set: &'a CommandSet, exe: &str) -> &'a Invocation {
    set.invocations
        .iter()
        .find(|i| i.exe == exe)
        .unwrap_or_else(|| {
            panic!(
                "no {exe} in {:?}",
                set.invocations.iter().map(|i| &i.exe).collect::<Vec<_>>()
            )
        })
}

fn set(cmd: &str) -> CommandSet {
    extract(cmd, Path::new("/work"), Some(Path::new("/home/dev")))
}

#[test]
fn program_names_are_normalized() {
    assert_eq!(program_name("/bin/rm"), "rm");
    assert_eq!(program_name("RM"), "rm");
    assert_eq!(program_name("./Rm"), "rm");
    assert_eq!(program_name("C:\\Windows\\cmd.exe"), "cmd");
}

#[test]
fn wrappers_are_stripped() {
    for cmd in [
        "sudo rm -rf /x",
        "sudo -u root -E rm -rf /x",
        "sudo -Eu root rm -rf /x",
        "env FOO=1 rm -rf /x",
        "env -i PATH=/bin rm -rf /x",
        "nice -n 10 rm -rf /x",
        "nohup rm -rf /x",
        "timeout 5 rm -rf /x",
        "timeout -s KILL 5s rm -rf /x",
        "command rm -rf /x",
        "exec rm -rf /x",
        "doas rm -rf /x",
        "stdbuf -o0 rm -rf /x",
        "busybox rm -rf /x",
        "sudo env nice -n5 rm -rf /x",
        "uv run rm -rf /x",
        "time rm -rf /x",
    ] {
        let s = set(cmd);
        let rm = find(&s, "rm");
        assert_eq!(
            rm.args()
                .iter()
                .map(|w| w.text.as_str())
                .collect::<Vec<_>>(),
            vec!["-rf", "/x"],
            "{cmd}"
        );
    }
    let s = set("sudo -u root rm -rf /x");
    assert_eq!(find(&s, "rm").wrappers, vec!["sudo"]);
}

#[test]
fn xargs_marks_dynamic_arguments() {
    let s = set("find . -name '*.tmp' | xargs rm -rf");
    let rm = find(&s, "rm");
    assert!(rm.dynamic_args);
    assert_eq!(rm.wrappers, vec!["xargs"]);
}

#[test]
fn nested_shell_strings_are_followed() {
    for cmd in [
        "bash -c 'rm -rf /x'",
        "sh -c \"rm -rf /x\"",
        "bash -lc 'rm -rf /x'",
        "zsh -ec 'echo hi; rm -rf /x'",
        "sudo sh -c 'rm -rf /x'",
        "eval 'rm -rf /x'",
        "eval rm -rf /x",
        "bash -c \"bash -c 'rm -rf /x'\"",
        "su -c 'rm -rf /x' root",
        "watch -n 1 rm -rf /x",
        "env -S 'rm -rf /x'",
        "flock /tmp/lock -c 'rm -rf /x'",
        "ssh prod-db 'rm -rf /x'",
        "git -c alias.x='!rm -rf /x' x",
    ] {
        assert!(
            exes(cmd).contains(&"rm".to_string()),
            "{cmd}: {:?}",
            exes(cmd)
        );
    }
}

#[test]
fn stdin_scripts_are_followed() {
    assert!(exes("bash <<EOF\nrm -rf /x\nEOF").contains(&"rm".into()));
    assert!(exes("sh <<< 'rm -rf /x'").contains(&"rm".into()));
    assert!(exes("echo 'rm -rf /x' | sh").contains(&"rm".into()));
    assert!(exes("printf 'rm -rf %s\\n' /x | bash").contains(&"rm".into()));
    let s = set("echo 'ls' | sh");
    assert_eq!(
        find(&s, "sh").executes,
        Some(Executes::Stdin { resolved: true })
    );
    let s = set("cat script | sh");
    assert_eq!(
        find(&s, "sh").executes,
        Some(Executes::Stdin { resolved: false })
    );
}

#[test]
fn find_exec_is_extracted() {
    let s = set("find / -name x -exec rm -rf {} \\;");
    let rm = find(&s, "rm");
    assert_eq!(rm.origin, Origin::FindExec);
    assert!(rm.dynamic_args);
    let s = set("find . -execdir sudo chmod 777 {} +");
    assert_eq!(find(&s, "chmod").wrappers, vec!["sudo"]);
}

#[test]
fn inline_code_system_calls_are_parsed() {
    assert!(exes("python3 -c 'import os; os.system(\"rm -rf /x\")'").contains(&"rm".into()));
    assert!(
        exes("node -e \"require('child_process').execSync('rm -rf /x')\"").contains(&"rm".into())
    );
    assert!(exes("ruby -e '`rm -rf /x`'").contains(&"rm".into()));
    assert!(exes("awk 'BEGIN { system(\"rm -rf /x\") }'").contains(&"rm".into()));
    assert!(exes("osascript -e 'do shell script \"rm -rf /x\"'").contains(&"rm".into()));
    let s = set("python -c 'print(1)'");
    assert!(matches!(
        find(&s, "python").executes,
        Some(Executes::InlineCode { .. })
    ));
}

#[test]
fn script_files_and_interpreters() {
    let s = set("bash install.sh");
    assert_eq!(
        find(&s, "bash").executes,
        Some(Executes::ScriptFile(Word::literal("install.sh")))
    );
    let s = set("python3 -m pip install x");
    assert_eq!(find(&s, "python3").executes, None);
    let s = set("curl x | python3");
    assert_eq!(
        find(&s, "python3").executes,
        Some(Executes::Stdin { resolved: false })
    );
    let s = set("bash -s -- --flag < script.sh");
    assert_eq!(
        find(&s, "bash").executes,
        Some(Executes::Stdin { resolved: false })
    );
}

#[test]
fn dynamic_programs_are_detected() {
    let s = set("$(echo rm) -rf /");
    assert!(s.invocations.iter().any(|i| i.exe_dynamic()));
    let s = set("$UNKNOWN -rf /");
    assert!(s.invocations.iter().any(|i| i.exe_dynamic()));
    let s = set("eval \"$CMD\"");
    assert!(!s.unresolved.is_empty());
    let s = set("bash -c \"$PAYLOAD\"");
    assert!(!s.unresolved.is_empty());
}

#[test]
fn cd_updates_working_directory() {
    let s = set("cd / && rm -rf *");
    assert_eq!(find(&s, "rm").cwd.as_deref(), Some(Path::new("/")));
    let s = set("cd sub; cd ..; cd other && rm x");
    assert_eq!(
        find(&s, "rm").cwd.as_deref(),
        Some(Path::new("/work/other"))
    );
    let s = set("cd && rm x");
    assert_eq!(find(&s, "rm").cwd.as_deref(), Some(Path::new("/home/dev")));
    let s = set("cd \"$DIR\" && rm x");
    assert_eq!(find(&s, "rm").cwd, None);
}

#[test]
fn canonical_form() {
    let s = set("FOO=1  /usr/bin/git   push  -f > out.log");
    assert_eq!(s.invocations[0].canonical(), "FOO=1 git push -f >out.log");
}

#[test]
fn flags_and_positionals() {
    let s = set("rm -fr -- -weird file");
    let rm = find(&s, "rm");
    assert!(rm.has_flag(Some('r'), &["--recursive"]));
    let pos: Vec<_> = rm.positionals().iter().map(|w| w.text.clone()).collect();
    assert_eq!(pos, vec!["-weird", "file"]);
}

#[test]
fn static_variables_are_propagated() {
    let s = set("x=rm; $x -rf /tmp/y");
    let rm = find(&s, "rm");
    assert_eq!(rm.args()[1].text, "/tmp/y");
    let s = set("F=.env; cat \"$F\"");
    assert_eq!(find(&s, "cat").args()[0].text, ".env");
    assert!(find(&s, "cat").args()[0].is_static());
    let s = set("export D=~/.ssh && tar czf out.tgz $D");
    assert_eq!(find(&s, "tar").args()[2].text, "/home/dev/.ssh");
    // Reassigned to something dynamic: no longer known.
    let s = set("F=.env; F=$(pick); cat $F");
    assert!(!find(&s, "cat").args()[0].is_static());
    // Prefix assignments apply to the command's environment, not its words.
    let s = set("F=.env cat $F");
    assert!(!find(&s, "cat").args()[0].is_static());
}
