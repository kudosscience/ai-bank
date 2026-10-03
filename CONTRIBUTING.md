# Contributing to ClawBank

Thanks for contributing.

## Before you start

- Read `/home/runner/work/clawbank/clawbank/CONTEXT.md` for domain vocabulary.
- Read relevant ADRs in `/home/runner/work/clawbank/clawbank/docs/adr` before changing architecture.
- Search existing issues before opening a new one.

## Development setup

1. Install stable Rust (`rustup`, `cargo`).
2. Clone the repository.
3. From `/home/runner/work/clawbank/clawbank`, run:

```bash
cargo test --all
```

Optional (required for `rust-check.sh audit`):

```bash
cargo install cargo-audit --locked
cargo install cargo-deny --locked
```

## Workflow

1. Create a branch for your change.
2. Keep changes focused and small.
3. Add or update tests when behavior changes.
4. Run the checks below before opening a pull request.
5. Open a PR with a clear summary and rationale.

## Required checks

Run the Rust quality gate script:

```bash
bash scripts/ci/rust-check.sh all
```

Run documentation/policy checks:

```bash
bash scripts/ci/context-check.sh
bash scripts/ci/adr-check.sh
bash scripts/ci/ci-sync-check.sh
```

If you have markdownlint installed, also run:

```bash
markdownlint-cli2 "**/*.md"
```

## Pull request guidance

- Explain what changed and why.
- Call out safety or security implications.
- Reference related issues (for example, `Closes #123`).
- Keep PRs reviewable; split unrelated work.

## Reporting security or safety concerns

Follow `/home/runner/work/clawbank/clawbank/SECURITY.md`.
