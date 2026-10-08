# Changelog

## 0.1.0 (unreleased)

First release.

- `sentinel init`, `run`, `check`, `log`, `status`, `policy`, `hook`
- POSIX/bash command analysis: quoting, escapes, `$'…'`, variables,
  substitutions, heredocs, wrappers (`sudo`, `env`, `xargs`, …), nested
  shells (`bash -c`, `eval`, `ssh`, `find -exec`, inline `os.system`)
- Detectors for destructive filesystem operations, git history rewrites and
  protected branches, remote code execution, obfuscation, privilege
  escalation, destructive infrastructure commands, package installs, network
  requests and uploads, secrets (files, content, environment, credential
  stores), and tampering with sentinel itself
- YAML policy language with deny > confirm > allow precedence, any/all
  matching, network allow/deny lists, and built-in tests
- Claude Code and Codex `PreToolUse` adapters; generic JSON protocol
- Confirmation prompt on the controlling terminal with per-session grants
- JSONL audit log with secret redaction
