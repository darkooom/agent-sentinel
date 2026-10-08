# Integrations

| agent / boundary | status | how | confirm becomes |
|---|---|---|---|
| **Claude Code** | ✅ supported | `PreToolUse` hook | Claude Code's own permission prompt (`ask`) |
| **OpenAI Codex CLI** | ✅ supported, experimental | `PreToolUse` hook | **deny** (Codex hooks cannot ask) |
| **Any shell** | ✅ supported | `sentinel run <command>` | terminal prompt; deny without a terminal |
| **Your own agent / harness** | ✅ supported | `sentinel hook generic` (JSON) or `sentinel check` | your harness decides |
| Cursor | ⏳ not yet | Cursor has `beforeShellExecution` hooks; no adapter yet | — |
| Gemini CLI | ⏳ not yet | Gemini CLI has `BeforeTool` hooks; no adapter yet | — |

The Claude Code and Codex adapters follow the protocols as published (links
below) and are covered by fixture tests in `tests/fixtures/`. They have not
been exercised against every agent release; if an agent changes its hook
format, please open an issue.

---

## Claude Code

Claude Code runs a `PreToolUse` hook before every tool call and waits for its
answer. This is enforced by Claude Code, not by the model.

### Setup

```bash
cd your-project
sentinel init --claude-code
```

This writes `.sentinel/policy.yml` and adds to `.claude/settings.local.json`
(a per-machine file, because it contains the absolute path of the binary):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [{ "type": "command", "command": "/path/to/sentinel hook claude-code", "timeout": 30 }]
      }
    ]
  }
}
```

To share the hook with a team through the committed `.claude/settings.json`,
use `"command": "sentinel hook claude-code"` and make sure everyone has
`sentinel` on their `PATH`. Restart Claude Code (or open `/hooks`) after
changing settings.

### What is inspected

| tool | becomes | notes |
|---|---|---|
| `Bash`, `PowerShell` | shell command | PowerShell commands are analyzed with the POSIX parser, which misses PowerShell-specific syntax |
| `Read` | file read | path classification and content scan for secrets |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | file write | new content is scanned for secrets; writes to hook configs and `.sentinel/` are tamper |
| `Grep` | file read of its `path` (and of `path/glob` when a glob is given) | |
| `WebFetch` | network request | host checked against the `network` section |
| `Glob`, `LS`, `WebSearch`, `TodoWrite` | nothing | they expose no file contents |
| anything else (MCP tools, `Agent`, …) | tool action | only `agent`/`tool`/`kind` conditions apply; allowed by default |

### Decisions

| sentinel | hook output | effect |
|---|---|---|
| deny | `permissionDecision: "deny"` | the tool call is blocked; the reason is shown to Claude |
| confirm | `permissionDecision: "ask"` | Claude Code asks you, showing sentinel's reason |
| allow | *no output* | Claude Code's normal permission rules apply. sentinel never auto-approves. |
| error | `permissionDecision: "ask"` | malformed input, broken policy or internal error: you decide |

Protocol: <https://code.claude.com/docs/en/hooks> (PreToolUse input and
decision control).

### Caveats

- If the `sentinel` binary is missing or not executable, Claude Code treats
  the hook as a non-blocking error and **proceeds**. `sentinel status` shows
  whether the hook is registered; keep the path in the settings valid.
- Claude Code resolves `Read`/`Write`/`Edit` paths to absolute paths before
  the hook runs, so relative spellings cannot bypass path rules.
- Policy discovery starts at `CLAUDE_PROJECT_DIR`, not at the current
  directory of the Bash tool, so an agent cannot `cd` into a directory with a
  laxer `.sentinel/policy.yml`.

---

## OpenAI Codex CLI (experimental)

Codex runs `PreToolUse` hooks for shell commands (`Bash`), `apply_patch`
edits, and MCP tools.

### Setup

`~/.codex/hooks.json` (all projects) or `<repo>/.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [{ "type": "command", "command": "sentinel hook codex", "timeout": 30 }]
      }
    ]
  }
}
```

Codex asks you to review and trust new hooks (`/hooks`) before they run.

### Decisions

| sentinel | hook output |
|---|---|
| deny | `permissionDecision: "deny"` |
| confirm | **`permissionDecision: "deny"`**, with a reason saying confirmation was required |
| allow | no output |
| error | `permissionDecision: "deny"` |

Codex parses `permissionDecision: "ask"` but does not support it yet: the hook
is marked failed and the tool call **proceeds**. So sentinel fails closed and
denies. Run the command yourself if it was intended, or relax the rule.

For `apply_patch`, every file named in the patch (`*** Add File:`,
`*** Update File:`, `*** Delete File:`, `*** Move to:`) becomes a file write,
with the added lines as content.

Protocol: <https://developers.openai.com/codex/hooks> and the JSON schemas in
[openai/codex `codex-rs/hooks/schema/generated`](https://github.com/openai/codex/tree/main/codex-rs/hooks/schema/generated).
Codex also documents hooks as "a useful guardrail, not a complete enforcement
boundary" — the same applies here. Use Codex's sandbox modes for containment.

---

## `sentinel run`

Wrap any command:

```bash
sentinel run "npm test && npm run lint"     # one argument: bash -c
sentinel run cargo test --workspace         # several arguments: executed directly
```

- allowed: runs, exit code passes through
- denied: panel on stderr, exit code **126**, nothing runs
- confirm: prompt on the controlling terminal (`/dev/tty`, never stdin);
  `[a]` allow once, `[s]` allow for this terminal session (same command, same
  directory, 12 hours), anything else denies. Without a terminal, or inside an
  agent TUI (`CLAUDECODE`/`AI_AGENT` set), it is denied.

`sentinel run` only protects what goes through it. `sentinel run bash` checks
`bash` and then starts an interactive shell; commands typed inside it are
**not** inspected, and sentinel says so.

---

## Generic protocol

For harnesses without a dedicated adapter. Send one action or an array on
stdin:

```bash
echo '{"kind":"shell","command":"git push -f origin main","cwd":"/repo","agent":"my-agent"}' \
  | sentinel hook generic
```

```json
{"decision":"deny","reason":"Force pushes to or deletes a protected branch","rule":"block-protected-branch-rewrite","risk":"critical","findings":[{"id":"git.protected-branch","risk":"critical","message":"Force push to protected branch 'main'"}]}
```

| field | for kind | |
|---|---|---|
| `kind` | all | `shell`, `file_read`, `file_write`, `network`, `tool` |
| `command` | `shell` | command line |
| `path` | `file_read`, `file_write` | path (relative to `cwd` or absolute) |
| `content` | `file_write` | optional; scanned for secrets, never logged |
| `url` | `network` | URL |
| `tool` | `tool` | tool name |
| `cwd` | all | defaults to sentinel's working directory |
| `agent`, `session` | all | recorded in the audit log |

Exit codes: `0` allow, `1` deny (also on any error), `3` confirm. For an
array, the most restrictive decision is returned. Asking the user on
`confirm` is the caller's job.

`sentinel check` offers the same evaluation from the command line
(`sentinel check "cmd"`, `--read PATH`, `--write PATH`, `--fetch URL`,
`--json`), with the same exit codes. See [`examples/`](../examples).

---

## Cursor and Gemini CLI

Both have blocking pre-execution hooks (Cursor: `beforeShellExecution`,
`beforeReadFile`, …; Gemini CLI: `BeforeTool`). Their JSON formats differ
from Claude Code's, and sentinel does not have adapters for them yet. They
are next on the roadmap; until then, sentinel is not integrated with them and
does not claim to be.
