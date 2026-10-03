# ClawBank

ClawBank is a Rust workspace for a node-centric banking model for LLM agents.

Today the repository includes the core identity and CLI foundation:

- Deterministic node identity (Ed25519 keypair → libp2p PeerId)
- Identity backup/restore (`export` / `import`)
- Local peer alias book (`peer add` / `peer list`)
- Safety, ADR, and verification documentation in `docs/`

## Repository layout

- `/home/runner/work/clawbank/clawbank/crates/clawbank`: CLI binary
- `/home/runner/work/clawbank/clawbank/crates/clawbank-identity`: identity, PeerId, signatures, petnames
- `/home/runner/work/clawbank/clawbank/crates/clawbank-safety`: safety policy crate
- `/home/runner/work/clawbank/clawbank/crates/clawbank-transport`: transport crate
- `/home/runner/work/clawbank/clawbank/docs`: ADRs, safety docs, agent docs

## Prerequisites

- Rust toolchain (stable)
- `cargo` and `rustup`

Optional for full local audit checks:

- `cargo-audit`
- `cargo-deny`

## Quick start

From `/home/runner/work/clawbank/clawbank`:

```bash
cargo run -p clawbank -- init
```

Initialize once, then back up identity material:

```bash
cargo run -p clawbank -- export > clawbank-identity-backup.txt
```

Restore identity from backup text:

```bash
cargo run -p clawbank -- import "$(cat clawbank-identity-backup.txt)"
```

Manage local peer aliases:

```bash
cargo run -p clawbank -- peer add <peer-id> <alias>
cargo run -p clawbank -- peer list
```

### Identity storage

By default, ClawBank stores local state under `~/.clawbank`:

- `identity.key`: node private key material
- `peers.json`: local alias book

Set `CLAWBANK_HOME` to override the data directory.

## Development checks

Use the same script CI uses:

```bash
bash scripts/ci/rust-check.sh all
```

Documentation and policy checks used in CI:

```bash
bash scripts/ci/context-check.sh
bash scripts/ci/adr-check.sh
bash scripts/ci/ci-sync-check.sh
```

## Security and safety

- Safety policy: `/home/runner/work/clawbank/clawbank/SAFETY.md`
- Security reporting: `/home/runner/work/clawbank/clawbank/SECURITY.md`

## Contributing

See `/home/runner/work/clawbank/clawbank/CONTRIBUTING.md`.
