# Contributing

Thanks for helping make coding agents safer to run.

## Most wanted

1. **Commands sentinel gets wrong.** A dangerous command that isn't flagged,
   or an everyday command that is. Add a case to
   `crates/sentinel-core/src/analysis/tests.rs` (there are sections per area)
   and fix the detector, or open an issue with the command.
2. **Agent adapters.** Cursor and Gemini CLI are next. An adapter is a parser
   and a renderer (`crates/sentinel-runtime/src/adapters/`); it must never
   fail open. Include fixtures shaped like the agent's documented payloads in
   `tests/fixtures/` and cite the protocol docs.

## Ground rules

- **No fake integrations.** If an agent cannot do something (e.g. Codex hooks
  cannot ask), say so in code comments and docs, and fail closed.
- **No claims the code doesn't back.** Security docs describe what is
  implemented, not what is planned.
- **Tests for behavior.** Every detector change comes with tests, including
  at least one evasion attempt.
- **Keep it small.** No async runtime, no network access, minimal dependencies.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

Try changes against real commands without touching your own state:

```bash
SENTINEL_HOME=$(mktemp -d) cargo run -q -- check --json "your command here"
```

New finding ids go in `crates/sentinel-core/src/finding.rs` (the catalog) and
in the table in `docs/policy.md`; a test enforces both.
