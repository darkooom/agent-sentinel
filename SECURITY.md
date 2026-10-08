# Security policy

agent-sentinel is a security tool, so bypasses matter.

## What counts as a vulnerability

- **Analyzer bypass**: a command, file access, or network request that does
  something the default policy should block or confirm, but sentinel reports
  as harmless. Obfuscation that defeats the parser is in scope.
- **Fail-open**: any input, policy or error condition that makes a hook or
  `sentinel run` allow something it would otherwise deny or confirm.
- **Secret leakage**: secret values appearing in the audit log, terminal
  output, hook responses, or session files.
- **Prompt spoofing**: a command that can change what the confirmation prompt
  displays, or approve itself.

Known, documented limitations (see [docs/security-model.md](docs/security-model.md))
are not vulnerabilities: sentinel does not see what programs do internally,
does not intercept network traffic, and provides no OS-level isolation.

## Reporting

Please report privately through GitHub's
[private vulnerability reporting](https://github.com/darkooom/agent-sentinel/security/advisories/new)
rather than a public issue. Include the command or payload, the policy (or
"default"), what sentinel decided, and what you expected.

You can expect an acknowledgement within a few days. Fixed bypasses get a
regression test in the analyzer test suite and a note in the changelog.
