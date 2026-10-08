# Hook fixtures

Payloads shaped like the ones each agent sends to a `PreToolUse` hook, used by
the CLI integration tests (`crates/sentinel-cli/tests/cli.rs`). `{{CWD}}` is
replaced with a temporary project directory at test time.

Field names follow the published protocols:

- Claude Code: https://code.claude.com/docs/en/hooks (PreToolUse input)
- Codex: https://developers.openai.com/codex/hooks and the JSON schemas in
  `openai/codex` under `codex-rs/hooks/schema/generated/`
