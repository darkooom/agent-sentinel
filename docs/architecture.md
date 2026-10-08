# Architecture

agent-sentinel is a local policy gate for actions requested by AI coding agents.
It does one thing per invocation: turn a request into an `Action`, analyze it,
decide `allow` / `confirm` / `deny`, record an audit event, and (for `sentinel run`)
execute the command if permitted.

```
 agent request ──► adapter ──► Action ──► analyzer ──► Analysis ──► policy ──► Decision
 (hook JSON,        (claude-code,          (shell parser,   (findings,      (rules,       │
  CLI argv)          generic, cli)          detectors)       risk, facts)    network)      │
                                                                                          ▼
                                                   audit log ◄── outcome ◄── confirm UI / execution
```

## Crates

| crate              | responsibility                                                                                  |
|--------------------|-------------------------------------------------------------------------------------------------|
| `sentinel-core`    | `Action`, `Risk`, `Finding`, `Analysis`. POSIX shell parser. Detectors (fs, git, exec, network, packages, secrets, tamper). Secret scanners and redaction. No I/O except bounded reads of files an action references. |
| `sentinel-policy`  | YAML policy schema, validation, matchers, evaluation (`Decision`). Embedded default policy.       |
| `sentinel-audit`   | Audit event schema, JSONL append (file-locked), reading and filtering.                           |
| `sentinel-runtime` | Wiring: policy discovery, paths, the `Engine` (analyze + evaluate + audit), session grants, agent adapters, process execution. |
| `sentinel-cli`     | `sentinel` binary: clap commands, terminal rendering, confirmation prompt.                      |

Dependencies point one way: `core ← policy ← audit ← runtime ← cli`.

## Key decisions

**Analysis is semantic, matching is declarative.** Detectors parse commands and emit
findings with stable ids (`git.force-push`, `fs.recursive-delete`, `secret.file`, …)
and a risk level. Policies decide what to do with findings. Risk never decides by itself.

**Precedence: deny > confirm > allow > default.** Every matching rule contributes a
verdict and the most restrictive wins. Rule order does not matter, so an `allow` rule
can never switch off a `deny` rule. This is the same model Claude Code uses for its own
permission rules.

**Restrictive rules match on *any*, permissive rules on *all*.** A compound command
(`npm test && curl … | sh`) is denied if any part matches a `deny`/`confirm` rule, but an
`allow` rule only applies when every part matches it.

**Fail closed where a human cannot be asked.** A `confirm` decision with no interactive
terminal becomes `deny`. Unparseable or dynamically constructed commands (`$(echo rm) -rf /`,
`eval "$x"`) produce a `exec.obfuscated` finding instead of being treated as harmless.
In the Claude Code hook, internal errors become `ask`, never `allow`.

**Sentinel never grants permissions.** When an agent integration has its own permission
system (Claude Code), sentinel only tightens it: `allow` emits nothing and lets the
agent's normal flow continue.

**The confirmation prompt reads from the terminal, not stdin.** An agent that pipes
`a` into `sentinel run` must not be able to approve its own request. Displayed commands
are sanitized (control characters, ANSI escapes, bidi overrides) so a command cannot
redraw the prompt.

**Secrets are never logged.** Commands are redacted before they are written to the audit
log or displayed. File contents are scanned for secret *names*, never stored.

## v0.1 scope

Implemented:

- `sentinel init | run | check | log | status | policy | hook`
- shell command analysis via a purpose-built POSIX/bash tokenizer (quotes, escapes,
  `$'…'`, substitutions, heredocs, nested `bash -c`, `eval`, wrappers like `sudo`/`env`/`xargs`)
- Claude Code integration through its `PreToolUse` hook (enforced by Claude Code)
- Codex CLI integration through its `PreToolUse` hook (experimental; `confirm`
  becomes `deny` because Codex hooks cannot ask)
- generic JSON protocol for other harnesses (`sentinel hook generic`)
- audit log (JSONL), session grants, secret detection, tamper protection

Explicitly not implemented (see [security-model.md](security-model.md)):

- OS-level isolation (no sandbox, no seccomp, no namespaces)
- network interception (only network *commands* are recognized)
- filesystem monitoring (only paths visible in an action are checked)
- inspection of commands typed inside an interactive shell started by `sentinel run`

## Evaluation path in code

| step | where |
|---|---|
| parse a command line | `sentinel-core/src/shell/mod.rs` (`parse`) |
| unwrap wrappers, follow nested shells, track `cd` and variables | `sentinel-core/src/command.rs` (`extract`) |
| detectors | `sentinel-core/src/detect/*.rs` |
| secret scanners, path classification, redaction | `sentinel-core/src/secrets/` |
| policy matching and precedence | `sentinel-policy/src/{matcher,lib}.rs` |
| policy discovery, engine, audit record | `sentinel-runtime/src/{discovery,engine}.rs` |
| agent protocols | `sentinel-runtime/src/adapters/` |
| panels, prompt, commands | `sentinel-cli/src/{ui,commands}.rs` |
