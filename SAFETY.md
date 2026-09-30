# ClawBank Safety Policy (SAFETY.md)

Version: 0.2.0
Effective: 2026-09-07

> Version: 0.2.0 | Effective: 2026-09-07 | Supersedes: safety/v0.1.0 | Branch: `main`
> | Maintainer/RSO: [@kudosscience](https://github.com/kudosscience) (Henry Ward)
> | Feedback: GitHub Issues with the `safety` label
> | Source of truth for levels: [ADR-0004](docs/adr/0004-safety-risk-levels.md)
> | Argument track: [MVP safety case](docs/safety/mvp-safety-case.md) (Safety 02, #36)
> | Document pattern: [ADR-0005](docs/adr/0005-safety-doc-pattern.md) | Evaluations: [ADR-0006](docs/adr/0006-safety-evaluation-framework.md)

## Preamble

ClawBank is a decentralised credit network for LLM agents with no board,
no cloud bills, and no central authority. This file is the durable public
safety commitment: what the network may do, what safeguards that requires,
why the MVP is safe, and how the commitment itself is versioned and
audited.

It follows the Responsible Scaling Policy grammar (public commitment, not
platform policy): proportional, iterative, and exportable. Like a BIP, it
serves as a collaborative record for proposing safety standards which node
operators voluntarily adopt by running satisfying code — forks remain
possible, and safety is achieved by legibility of the fork, not by central
enforcement.

Safety is part of the MVP with maintainer (RSO) governance. Commitments
here are forkable, locally verifiable, and survive without a hosted
service. Public by default, redact by rule: thresholds, safeguards, and
evaluation summaries are public; raw exploit detail and peer-identifying
data stay internal and redactions are marked, never silent
(per [ADR-0005](docs/adr/0005-safety-doc-pattern.md) and
[risk-reports.md](docs/safety/risk-reports.md)).

This is the Docs 01 core ([#38](https://github.com/kudosscience/clawbank/issues/38)):
preamble, FAL background, the threshold/safeguard matrix, the Safety 02
justification core, versioning, and the Changelog — extended by Docs 02
([#39](https://github.com/kudosscience/clawbank/issues/39)), which adds
the operating assessment procedures (§§5–7), deployment outcomes and the
pause rule (§8), governance (§9), and Appendices A–C/E–F below;
signing, tags, and attestation land in Docs 03
([#40](https://github.com/kudosscience/clawbank/issues/40)). Those tracks
extend this file — they do not fork its content.

## 1. Background — the FAL model (imported, not restated)

Normative level definitions live in exactly one place:
[ADR-0004](docs/adr/0004-safety-risk-levels.md). This section imports them
by reference and never restates them. Any wording below that looks like a
definition is a non-normative summary; on any divergence ADR-0004 wins.

Financial Autonomy Levels (FAL) are sets of required safeguards tied to
reversible capability thresholds, modelled on Anthropic's ASL: FAL-1
Sandbox, FAL-2 Virtual credit network (MVP), FAL-3 Real-value-adjacent,
FAL-4 Autonomous macro-economy (undefined today; committed to define before
reaching FAL-3). Each level inherits the previous bundle monotonically and
is re-evaluated whenever safeguards upgrade.

The network ships at **FAL-2**. The level is declared mechanically in one
constant — `clawbank_safety::FAL_LEVEL` in
`crates/clawbank-safety/src/lib.rs` (currently `2`) — pinned by test and
enforced by the pause-rule gate in
`crates/clawbank-safety/tests/fal_gate.rs`. Operator procedure:
[fal-level.md](docs/safety/fal-level.md).

The full harm catalogue (12 families with deployed precedents), the
blast-radius table, and the RSP-to-FAL mapping are in the ADR-0004 research
record; this file locks nothing beyond pointing at them.

## 2. Capability thresholds and required safeguards

Source of truth: [ADR-0004](docs/adr/0004-safety-risk-levels.md). The table
below is a non-normative summary of it — it creates no second normative
copy. The "Required safeguards" column states what each level *requires*,
not what is implemented today (implementation status lives in §4 and
[§5b of the safety case](docs/safety/mvp-safety-case.md#5b-planned-explicitly-not-done-tracked-by-ticket)).

| Level | Name | What agents may do | Required safeguards (summary) |
| ----- | ---- | ------------------ | ----------------------------- |
| FAL-1 | Sandbox | Single-node/LAN, non-transferable or trivial balances, no P2P/reputation | Local `0o600` key storage only |
| FAL-2 | Virtual credit network (**MVP — ship here**) | Fixed-supply virtual credits, genesis mint only, P2P transfers, replicated ledger, history-derived reputation | Typed validated transfers, rate limits + message scoring, tenure-weighted reputation with whitewash cost, explicit fork-choice + social-fork checkpoint, authenticated transport, relay caps, `cargo audit`/`deny` |
| FAL-3 | Real-value-adjacent | Escrow (incl. HTLC/multi-sig), lending/borrowing, margin/yield, fiat/crypto bridges, compute marketplace, policy-based autonomous spending | FAL-2 bundle **plus** defense-in-depth (spending caps/allow-lists, inline anomaly classifier, async ledger analysis, pause/freeze rapid response) **plus** the 17-control subset (multi-party mint/bridge auth, SLSA provenance, audit log/SIEM, honeypot escrow, external red-team), Risk Reports + external reviewer |
| FAL-4 | Autonomous macro-economy | Recursive credit-to-compute earn loops persisting without human re-auth, systemic external-market impact | Undefined today; committed to define before reaching FAL-3 |

Re-evaluation commitment: thresholds are re-visited whenever safeguards
upgrade. Crossing to FAL-3 requires the pause-rule evidence in order —
safeguards (ADR-0004 FAL-3 bundle + 17-control subset), evaluations
(ADR-0006 FAL-3 harness showing no meaningful catastrophic misuse),
reviewer (maintainer plus external, recorded here and in a per-release Risk
Report) — never a bare constant flip.

## 3. Justification core — why FAL-2 is safe (housed from Safety 02)

This section houses the published Safety 02 argument
([mvp-safety-case.md](docs/safety/mvp-safety-case.md), [#36](https://github.com/kudosscience/clawbank/issues/36))
as the justification core of this commitment. It imports that file's
reasoning without duplicating it: summaries below point at the safety case
for the full text, and safeguard statuses point at its §5 legend
(**[Implemented]** / **[Planned — #N]** / **[Procedural]**).

### 3.1 Placement: the MVP is FAL-2

The MVP's design scope is a virtual credit network and nothing more (scope,
not implementation status — see §4): fixed supply (one genesis mint of
`SUPPLY = 1_000_000_000_000_000` base units, no minting after genesis per
[ADR-0011](docs/adr/0011-genesis.md)), virtual-only (ledger entries between
pseudonymous node keypairs, no redemption path, no bridge, nothing leaves
the network), and no leverage (no escrow, lending, margin, marketplace, or
autonomous-spending policy — enforced by the gate while `FAL_LEVEL < 3`).
Full placement text: [safety case §2](docs/safety/mvp-safety-case.md#2-placement-the-mvp-is-fal-2).

### 3.2 The contained-blast-radius argument

Fixed supply **plus** virtual-only **plus** no leverage bounds the worst
case to recoverable in-network harm — never external financial loss. The
adversary's ceiling at FAL-2 is ledger corruption, reputation collapse, and
denial of service via social fork, each recoverable by checkpointing and
re-joining; catastrophic external harm requires a bridge or leverage
primitive the gate forbids. The bound holds of the specified FAL-2 design
and becomes an enforced guarantee as the §4 planned safeguards land. Full
argument: [safety case §3](docs/safety/mvp-safety-case.md#3-the-contained-blast-radius-argument).

### 3.3 What FAL-2 excludes (FAL-3 triggers)

The following are **not** in the MVP. While `FAL_LEVEL < 3` the gate fails
the build if any appears anywhere outside allowlisted prose: escrow
(including HTLC and multi-sig escrow), lending and borrowing (loans),
margin and yield, fiat and crypto bridges, compute marketplace,
policy-based autonomous spending. Raising the level requires the pause-rule
evidence in order (see §2). Full trigger list and procedure:
[safety case §4](docs/safety/mvp-safety-case.md#4-what-fal-2-excludes-fal-3-triggers)
and [fal-level.md](docs/safety/fal-level.md).

## 4. Safeguards assessment (summary — statuses live in the safety case)

Every safeguard claim carries exactly one status from the safety-case
legend. This file states the shape; [safety case §5](docs/safety/mvp-safety-case.md#5-safeguard-claims-and-their-evidence)
owns the evidence links and stays the single content pipeline.

Implemented today (§5a): the FAL level is declared in one constant and
pinned by test (S1), no FAL-3 capability can land without failing the build
locally and in CI (S2), node keys are Ed25519 with owner-only persistence
and permission repair (S3), backup/restore is validated-before-write (S4),
and dependency risk is gated by `cargo audit` + `cargo deny` (S5).

Planned — explicitly not done, tracked by ticket (§5b): validated
transfers (P1), gossip/sync validation (P2), fork-choice with equivocation
evidence and checkpoints (P3), signed genesis artifact and recovery runbook
(P4), tenure-weighted reputation with whitewash cost (P5), scoring plus
rate limits plus relay caps (P6), authenticated transport with
domain-separated signatures (P7), the local `cargo test` FAL-2 proof
harness (P8), per-release risk notes (P9), and this document track itself
(P10). No other safeguard is claimed; anything not in §5a is still to
build, and §5b names the ticket that must build it.

Evaluation posture: today the proof is the enforced subset (S1–S5) run in
CI on every PR; the full FAL-2 proof (P8 harness per release plus the
6-month heartbeat, with pause-trigger and coverage/publish dates per
ADR-0006) is planned ([#41](https://github.com/kudosscience/clawbank/issues/41),
[#42](https://github.com/kudosscience/clawbank/issues/42),
[#43](https://github.com/kudosscience/clawbank/issues/43)). Declaring FAL-2
names the design scope (per ADR-0004) and the level the gate pins — it does
not claim the rest of the FAL-2 bundle is done, and the S2 term gate proves
only the absence of FAL-3 capabilities, not the completeness of FAL-2
controls. Until that harness lands, the case rests on the blast-radius
bound plus the implemented gates, not on adversarial results that do not
yet exist. Full posture: [safety case §6](docs/safety/mvp-safety-case.md#6-evaluation-posture-what-proves-it).

## 5. Capability assessment (procedure a reviewer can execute)

Purpose: confirm the tree still implements FAL-2 scope and nothing more.
A reviewer with a checkout and a Rust toolchain runs C1–C5 in order;
any failure is a pause-rule event (see §8), not a judgement call.

- C1 — Level pin. Confirm the mechanical declaration still reads `2`
  and the pin test holds it:

  ```sh
  grep -n "pub const FAL_LEVEL" crates/clawbank-safety/src/lib.rs
  cargo test -p clawbank-safety --test fal_gate fal_level_pins_mvp_at_two
  ```

  Pass: constant is `2`, test green. A bare constant flip without the
  §8 evidence changes nothing — the procedure below still applies.

- C2 — No FAL-3 capability present. Run the pause-rule gate, which
  fails the build while `FAL_LEVEL < 3` if any gated capability
  appears anywhere outside allowlisted prose:

  ```sh
  cargo test -p clawbank-safety --test fal_gate no_fal3_capabilities_below_fal3
  ```

  or equivalently `bash scripts/ci/rust-check.sh test` (the `rust-test`
  CI job runs `cargo test --all`, so every PR runs the gate). Pass:
  suite green. Fail output names the file and the matched term —
  that file is the escalation trigger (see §8.4).

- C3 — Commitment legibility. Confirm this file still states the
  FAL-3 threshold list, so allowlisting it cannot gut the commitment:

  ```sh
  cargo test -p clawbank-safety --test fal_gate safety_md_states_fal3_thresholds
  ```

  Pass: the escrow, lending, borrowing, margin, yield, bridge,
  marketplace, and autonomous-spending markers are all present
  (§3.3 restates them; Appendix C dossiers them).

- C4 — Placement spot-check. Confirm the three FAL-2 design-scope
  claims in §3.1 still hold of the tree: fixed supply (one genesis
  mint per [ADR-0011](docs/adr/0011-genesis.md), no post-genesis mint
  path), virtual-only (no redemption path, no bridge), no leverage
  (no escrow, lending, margin, marketplace, or autonomous-spending
  policy). Method: C2 green, plus a tree review the gate cannot do
  for you — the gate matches FAL-3 trigger *terms*, so a
  neutrally-named mint, redemption, or leverage path would pass it
  unnoticed. Search the current tree (not just the log) for
  supply-creating paths outside the genesis track, for
  redemption/convertibility paths, and for leverage-adjacent paths,
  then review `git log --oneline` for FAL-relevant changes since the
  last Risk Report. Any doubtful file is treated as a C2 hit until
  the gate confirms otherwise — and a capability the gate cannot see
  is a gate-coverage gap: file a `safety`-labelled issue naming the
  term to add.

- C5 — Record the verdict. Write it into the per-release Risk Report
  ([template](docs/safety/risk-report-template.md), procedure
  [risk-reports.md](docs/safety/risk-reports.md)): either **FAL-2
  reaffirmed** (C1–C4 green, gate names no file) or **escalation to
  FAL-3 required** (name the triggering capability and halt the
  release per §8). Full placement text:
  [safety case §2](docs/safety/mvp-safety-case.md#2-placement-the-mvp-is-fal-2).

## 6. Safeguards assessment (procedure a reviewer can execute)

Every safeguard claim carries exactly one status from the safety-case
legend (**[Implemented]** / **[Planned — #N]** / **[Procedural]**).
This procedure verifies the statuses; it never upgrades a status by
prose — only landed code or procedure changes a row, via its ticket.

- G1 — Implemented subset (S1–S5). Re-run what CI enforces on every
  PR and confirm each claim in
  [safety case §5a](docs/safety/mvp-safety-case.md#5a-implemented-today):

  ```sh
  bash scripts/ci/rust-check.sh test   # S1–S4: FAL pin, gate, identity suite
  bash scripts/ci/rust-check.sh audit  # S5: cargo audit + cargo deny
  ```

  Spot-check the evidence links: S1 `FAL_LEVEL` in
  `crates/clawbank-safety/src/lib.rs` plus the pin test; S2 the gate
  test run in the `rust-test` CI job (`.github/workflows/ci.yml`);
  S3–S4 the identity lifecycle in `crates/clawbank-identity/`; S5
  `deny.toml` plus the `rust-audit` job. Pass: all green and every
  link resolves to shipped code.

- G2 — Planned set (P1–P10). Confirm each row of
  [safety case §5b](docs/safety/mvp-safety-case.md#5b-planned-explicitly-not-done-tracked-by-ticket)
  still names its tracking ticket and that no row is claimed as done:
  P1 transfers, P2 gossip/sync, P3 fork-choice/evidence, P4 genesis
  artifact/recovery, P5 reputation, P6 scoring/rate-limits/relay-caps,
  P7 transport, P8 proof harness
  ([#41](https://github.com/kudosscience/clawbank/issues/41),
  [#42](https://github.com/kudosscience/clawbank/issues/42),
  [#43](https://github.com/kudosscience/clawbank/issues/43)), P9 risk
  notes ([#37](https://github.com/kudosscience/clawbank/issues/37)),
  P10 this document track
  ([#38](https://github.com/kudosscience/clawbank/issues/38),
  [#39](https://github.com/kudosscience/clawbank/issues/39),
  [#40](https://github.com/kudosscience/clawbank/issues/40)).
  Method: open each linked ticket; if its required deliverable has
  not landed, the row stays **[Planned]** and the Risk Report lists
  it under Known gaps. Completion is row-specific: implementation
  safeguards require the ticket's code to land; documentation tracks
  such as P9 and P10 require the documented procedure or artifact to
  land. No row closes by an edit here alone.

- G3 — No other safeguard is claimed. Anything not in §5a of the
  safety case is still to build by construction. If a release note or
  PR description claims a safeguard outside §5a/§5b, the assessment
  fails until the claim is removed or §5b gains the row with its
  ticket.

- G4 — Record the outcome in the Risk Report's Evaluations-run and
  Known-gaps sections, naming what was run (commands plus outcomes,
  including what was NOT run) per
  [risk-reports.md](docs/safety/risk-reports.md). A missing harness
  run is a known gap with its ticket, never a silent omission.

## 7. Follow-up assessment (procedure a reviewer can execute)

Follow-up is the cadence that keeps §§5–6 honest after the release.
Each trigger below names who acts and what lands; the Risk Report
template enforces the shape and the release gate enforces its
presence.

- F1 — Every FAL-relevant release. Any release touching `crates/*`
  or transfer/reputation/ledger logic ships with a fresh filled note
  at `docs/safety/risk-report-YYYY-MM-DD.md` (dated by coverage end).
  Copy the template, never edit it in place. The note must carry:
  evaluations run, FAL verdict, `coverage_date` versus `published`
  dates, the full evaluated commit SHA, known gaps each with its
  tracking ticket, an explicit Redactions section (`None` stated, or
  one `[REDACTED — category — N tokens withheld]` marker per
  withheld item), and the Attestation section. Raw exploit detail
  and peer-identifying data are forbidden in the note by rule.

- F2 — Heartbeat. At least every 6 months a note (or a heartbeat
  entry in `docs/safety/updates.md` pointing at one) lands even with
  no release, so coverage never silently drifts (depth over
  frequency, RSP v2.0 3→6-month lesson per ADR-0005).

- F3 — On safeguard upgrades. Thresholds are re-evaluated whenever
  safeguards change (RSP v2.1 practice): the note records the
  re-evaluation outcome, and a level rise additionally follows §8.5
  in order.

- F4 — On pause. Within 7 days of an emergency `pause/YYYY-MM-DD`
  tag, a full report follows under a `safety`-labelled issue (see
  §8.3 and [ADR-0006](docs/adr/0006-safety-evaluation-framework.md)).

- F5 — Verify before sign-off. Run the gate the release workflow
  runs and confirm the note it checks:

  ```sh
  bash scripts/ci/release-gate.sh safety 0.2.0   # Version header check
  bash scripts/ci/release-gate.sh code <version> # note shape + SHA + gaps + redactions
  ```

  Freshness is a maintainer duty on top of the structural checks:
  cut the release tag at the evaluated commit (or re-run the suite
  and write a fresh note) — reusing a stale note passes the shape
  checks but fails review. Full cadence, sign-off, and redaction
  rules: [risk-reports.md](docs/safety/risk-reports.md). Annual
  procedural self-review (`cargo audit`/`deny` + SLSA check;
  third-party review only at FAL-3+) checks whether §§5–7 were
  actually followed.

## 8. Deployment and scaling — the pause rule (Continue / Restrict)

The pause rule is the deployment gate: a capability proposal either
has its evidence in order and the network continues, or it does not
and the release is restricted until it does. Flipping `FAL_LEVEL`
without evidence changes nothing.

### 8.1 The rule

While `FAL_LEVEL < 3`, any appearance of a FAL-3-gated capability
outside allowlisted prose fails the build (C2), blocks the PR, and
halts the release — until the §8.5 evidence lands in order. A
proposal document never satisfies the rule; only safeguards plus
harness plus reviewer do. Operator procedure:
[fal-level.md](docs/safety/fal-level.md).

### 8.2 Continue — worked example

PR "Bump dust-threshold test vectors, no capability change": the
gate suite is green (`no_fal3_capabilities_below_fal3` names no
file), C1–C4 reaffirm FAL-2 scope, G1 re-pins S1–S5, the Risk Report
records **FAL-2 reaffirmed** with the evaluated commit SHA and
coverage/published dates, the maintainer merges as a standard change
(§9.3 Tier 0), and the release proceeds. The Changelog gains no
threshold row; the note's Known gaps still list P1–P10 tickets.

### 8.3 Restrict — worked example

PR "Add escrow settlement module (`Escrow` struct with HTLC
preimage check)": the gate fails —

```text
FAL-3-gated capability found at FAL-2; raising the level requires
the pause-gate evidence (safeguards + evaluations + external reviewer,
see docs/safety/fal-level.md), not just new code:
  crates/clawbank/src/escrow_settlement.rs: escrow, htlc
```

The PR is blocked however correct the code looks. The maintainer (or
anyone — no prior permission needed) cuts an emergency pause tag
`git tag -s pause/2026-09-07`, opens a `safety`-labelled issue
naming the triggering capability, and publishes the full report
within 7 days. The release halts; the module lands only after the
§8.5 evidence arrives in order and the level actually rises.
Good-faith false alarms are welcomed under the §9.4
non-retaliation commitment — a needless pause costs less than a
missed one.

### 8.4 Escalation triggers (exhaustive)

Each of the following, anywhere outside allowlisted prose while
`FAL_LEVEL < 3`, trips the gate and triggers §8.3: escrow
(including HTLC and multi-sig escrow), lending and borrowing
(loans), margin and yield, fiat and crypto bridges, compute
marketplace, policy-based autonomous spending. The gate matches
case-, separator-, and camelCase-insensitively, so renaming the
identifier does not dodge it; the full trigger list and allowlist
are the gate test plus [fal-level.md](docs/safety/fal-level.md),
and Appendix C dossiers each trigger.

### 8.5 Raising the level (evidence in order, never a bare flip)

A rise to FAL-3 requires, in this order:

1. **Safeguards** — the ADR-0004 FAL-3 defense-in-depth bundle
   (spending caps/allow-lists, inline anomaly classifier, async
   ledger analysis, pause/freeze rapid response) plus the 17-control
   subset (multi-party mint/bridge auth, SLSA provenance, audit
   log/SIEM, honeypot escrow, external red-team).
2. **Evaluations** — the ADR-0006 FAL-3 harness passes, showing no
   meaningful catastrophic misuse under adversarial testing.
3. **Reviewer** — the maintainer plus an external reviewer sign off,
   recorded here (Appendix E + Changelog) and in a per-release Risk
   Report.

Only then may `FAL_LEVEL` be raised and the gate's allowlist
updated. FAL-4 stays undefined today by design; it is committed to
be defined before reaching FAL-3.

## 9. Governance and transparency

Downscaled on purpose: what a single maintainer can actually follow,
with the external check arriving exactly where the level rises.

- **Safety decision-maker (maintainer-as-RSO).** The maintainer —
  [@kudosscience](https://github.com/kudosscience) (Henry Ward),
  default owner for everything per `.github/CODEOWNERS` — decides
  the FAL level, merges `SAFETY.md` changes, and owns the pause
  decision, per [ADR-0004](docs/adr/0004-safety-risk-levels.md) and
  [ADR-0005](docs/adr/0005-safety-doc-pattern.md). Duties: run §§5–7
  per release, keep coverage fresh (F5), cut the pause tag when §8.3
  fires, and publish the heartbeat (F2) even with no release.

- **External reviewer pool.** Threshold rises and FAL-3 features
  require a maintainer **plus** an external reviewer; no single
  party raises the level alone. The pool lives in Appendix E: each
  entry names the reviewer, scope, and sign-off date, and each
  sign-off is additionally recorded in the Changelog and the
  per-release Risk Report. At FAL-2 the pool seats are vacant by
  design (there is nothing at this level that needs an external
  sign-off); a seat must be filled before any FAL-3 evidence is
  accepted. Third-party review beyond that arrives only at FAL-3+.

- **PR gating tiers.** Every change lands through exactly one tier:

  | Tier | Change | Gate |
  | ---- | ------ | ---- |
  | Tier 0 — standard | Any change that keeps FAL-2 scope (code, docs, `SAFETY.md` wording that states no new threshold) | Maintainer review + merge; §§5–7 run; gate suite green |
  | Tier 1 — threshold | Any `SAFETY.md` threshold change or `FAL_LEVEL` rise | Tier 0 **plus** external reviewer sign-off recorded in Appendix E + Changelog + Risk Report; §8.5 evidence in order |
  | Tier 2 — FAL-3 feature | Any escrow/lending/borrowing/margin/yield/bridge/marketplace/autonomous-spending code | Blocked until §8.5 lands in full — safeguards, harness result, both reviewers — never a bare constant flip |
  | Emergency — pause | `git tag -s pause/YYYY-MM-DD` | No prior permission; followed by a `safety`-labelled issue plus the 7-day full report |

- **Non-retaliation commitment.** Anyone may raise a safety concern
  — as an issue with the `safety` label, as a PR, or as a pause
  request — without fear of retaliation, exclusion, or reputational
  penalty. Good-faith false alarms are welcomed: the cost of a
  needless pause is accepted as the price of never missing a real
  one. Emergency pause needs no prior permission.

- **Transparency.** Public by default, redact by rule: thresholds,
  safeguards, and evaluation summaries are public; raw exploit
  detail and peer-identifying data stay internal, and redactions are
  marked (`[REDACTED — category — N tokens withheld]`), never
  silent — per [ADR-0005](docs/adr/0005-safety-doc-pattern.md) and
  [risk-reports.md](docs/safety/risk-reports.md). Auditability is
  git plus Sigstore/Rekor: signed `safety/v*` tags with `git
  verify-tag` (keys in-repo at
  [MAINTAINER_PUBKEYS.asc](docs/safety/MAINTAINER_PUBKEYS.asc)),
  redline diffs with compare URLs in the Changelog, and per-release
  provenance bundles — end to end in
  [verify-runbook.md](docs/safety/verify-runbook.md).
  Full governance text:
  [safety case §7](docs/safety/mvp-safety-case.md#7-governance-and-non-retaliation).
  Per-release cadence, sign-off, and redaction rules:
  [risk-reports.md](docs/safety/risk-reports.md). Pause procedure:
  [fal-level.md](docs/safety/fal-level.md).

## Appendix A: Glossary

Domain terms are owned by [`CONTEXT.md`](CONTEXT.md) and imported
here without restating their definitions — on any divergence
`CONTEXT.md` wins for domain terms, ADR-0004 wins for FAL terms:

- **Credit / Base unit / Account / Transfer** — the value model
  (virtual, fixed-supply, fungible; 1 credit = 1,000,000 base units;
  one keypair, one account).
- **Genesis / Genesis artifact** — the one-time mint event versus
  the signed file recording its outcome (supply plus balances).
- **Checkpoint / Social fork** — the signed anchor all nodes agree
  to extend, versus the community re-joining under a new artifact or
  checkpoint after corruption or rejected distribution. Costs time
  and trust, never external funds.
- **Reputation** — the history-derived score. Display and routing
  guidance only.
- **Financial Autonomy Level (FAL)** — the risk tier of what agents
  may do with credits. Normative definitions live in exactly one
  place: [ADR-0004](docs/adr/0004-safety-risk-levels.md); §1 and
  Appendix C here are non-normative summaries.
- **RSO (Responsible Scaling Officer analogue)** — the safety
  decision-maker. At ClawBank this is the maintainer (§9), not a
  separate officer or board.
- **Risk Report** — the per-release filled risk note at
  `docs/safety/risk-report-YYYY-MM-DD.md` (shape:
  [template](docs/safety/risk-report-template.md); procedure:
  [risk-reports.md](docs/safety/risk-reports.md)). The evidence to
  this file's commitment.
- **coverage_date / published** — the last day the evaluations
  describe versus the day the note was written (intentionally
  distinct; the gap is visible, never hidden).
- **Pause tag** — the signed emergency marker
  `git tag -s pause/YYYY-MM-DD`, cut with no prior permission and
  followed by a `safety`-labelled issue plus the 7-day full report.
- **Redaction marker** — `[REDACTED — category — N tokens
  withheld]`, one per withheld item. Redactions are marked, never
  silent.
- **Continue / Restrict** — the two pause-rule outcomes (§8):
  the release proceeds on reaffirmed FAL-2 evidence, or it halts
  until the FAL-3 evidence lands in order.

## Appendix B: FAL-2 standard (non-normative summary)

Source of truth: [ADR-0004](docs/adr/0004-safety-risk-levels.md).
This appendix states what "FAL-2" requires of the network; §4 and
[safety case §5](docs/safety/mvp-safety-case.md#5-safeguard-claims-and-their-evidence)
state what is implemented today. The standard is:

- Fixed-supply virtual credits: one genesis mint of
  `SUPPLY = 1_000_000_000_000_000` base units, no minting after
  genesis ([ADR-0011](docs/adr/0011-genesis.md)).
- Virtual-only: ledger entries between pseudonymous node keypairs;
  no redemption path, no fiat or crypto bridge, nothing leaves the
  network.
- No leverage: no escrow, lending/borrowing, margin/yield,
  marketplace, or autonomous-spending policy.
- Required safeguard bundle: typed validated transfers (dust
  threshold, per-sender nonce, Ed25519 domain-separated signature,
  supply invariant), per-peer rate limits plus gossipsub scoring,
  tenure-weighted reputation with decay, diversity, and whitewash
  cost (new PeerId starts at zero), explicit fork-choice plus
  social-fork checkpoint, authenticated transport (Noise/TLS PeerId
  verify), relay caps, and `cargo audit`/`deny` gating.
- Required evaluation bundle per
  [ADR-0006](docs/adr/0006-safety-evaluation-framework.md): local
  `cargo test` transaction integrity (double-spend, replay/nonce,
  supply invariant under partition, deterministic fork-choice),
  Sybil N=50 spot-check, circular-trade/whitewash checks, dust flood
  at 10x rate versus relay caps, plus the pause-trigger test — run
  every FAL-relevant release and at least every 6 months, with
  coverage/published dates.

## Appendix C: Detailed threshold dossier (non-normative summary)

Source of truth: [ADR-0004](docs/adr/0004-safety-risk-levels.md).
FAL-3 is triggered by any of the following leaving prose and
entering the tree (see §8.4 and
[fal-level.md](docs/safety/fal-level.md) for the enforced list):

| Trigger | Concrete mechanisms that trip it |
| ------- | -------------------------------- |
| Escrow (including HTLC and multi-sig escrow) | escrow contracts, HTLC preimage/hash locks, multi-sig (`multisig` / `multi sig`) custody |
| Lending and borrowing (loans) | lending vaults/pools, borrowing flows, borrower/lender roles |
| Margin and yield | margin positions, yield farming or interest accrual |
| Fiat and crypto bridges | fiat on/off-ramps, crypto bridge lock/mint or redemption paths |
| Compute marketplace | compute market listings, buy/sell compute for credits |
| Policy-based autonomous spending | spending policies, autonomous-spend loops (`autospend`, `auto spend`, `spending policy`) persisting without human re-auth |

FAL-4 (autonomous macro-economy: recursive credit-to-compute earn
loops persisting without human re-auth with systemic
external-market impact) is undefined today by design; it is
committed to be defined before reaching FAL-3. Each level inherits
the previous bundle monotonically and is re-evaluated whenever
safeguards upgrade; crossing to FAL-3 requires the §8.5 evidence in
order — never a bare constant flip.

## Appendix D: Changelog

Every change to this commitment after `v0.1.0` gets a row below (newest
first) with a redline. Redlines are git diffs between signed safety tags
(`git diff safety/vX..safety/vY -- SAFETY.md`) with a GitHub compare URL;
the release gate (`scripts/ci/release-gate.sh`) enforces that the
`Version:` header above equals the tag being cut.

| Version | Date | Change | Redline |
| ------- | ---- | ------ | ------- |
| 0.2.0 | 2026-09-07 | Docs 02 operating sections: reviewer-executable capability/safeguards/follow-up procedures (§§5–7), deployment outcomes with Continue/Restrict worked examples and escalation triggers (§8), downscaled maintainer-as-RSO governance with PR gating tiers and anti-retaliation (§9), and Appendices A–C/E–F (glossary, FAL-2 standard, threshold dossier, reviewers, compliance checklist). No threshold or safeguard-status change; FAL-2 reaffirmed. | `git diff safety/v0.1.0..safety/v0.2.0 -- SAFETY.md` — compare `https://github.com/kudosscience/clawbank/compare/safety/v0.1.0...safety/v0.2.0` |
| 0.1.0 | 2026-09-07 | Initial Docs 01 core: preamble, FAL background imported from ADR-0004, threshold/safeguard matrix (non-normative summary), Safety 02 justification core housed by reference, Version/Effective header, and this Changelog discipline. Operating assessment procedures, deployment/governance text, and Appendices A–C/E–F deferred to Docs 02 (#39); signing/tags/attestation deferred to Docs 03 (#40). | Initial version — no prior safety tag; entire file is the change. Verify with `git show safety/v0.1.0:SAFETY.md`. Future rows link `https://github.com/kudosscience/clawbank/compare/safety/vX...safety/vY` |

Verification (reproduces the latest entry once the tag is cut):

```sh
bash scripts/ci/release-gate.sh safety 0.2.0
git show safety/v0.2.0:SAFETY.md | grep -m1 -E '^Version:'
# redline for the latest entry:
# git diff safety/v0.1.0..safety/v0.2.0 -- SAFETY.md
```

## Appendix E: Reviewers

Sign-off is recorded here, in the Changelog, and in the per-release
Risk Report — all three, so no single record carries the decision
alone.

| Role | Name | Scope | Sign-off |
| ---- | ---- | ----- | -------- |
| Maintainer / RSO | [@kudosscience](https://github.com/kudosscience) (Henry Ward) | FAL level, `SAFETY.md` merges, pause decision; §§5–7 per release | Standing — see `.github/CODEOWNERS` |
| External reviewer — seat 1 | *Vacant at FAL-2* | Threshold rises and FAL-3 features (Tier 1/2) | Must be filled before any FAL-3 evidence is accepted |
| External reviewer — seat 2+ | *Unfilled* | Additional scope as needed at FAL-3+ | — |

Rules: at FAL-2 the external seats are vacant by design — nothing at
this level needs an external sign-off, and standard changes merge on
maintainer review alone. A threshold change or FAL-3 feature with an
empty reviewer table fails review even if safeguards and harness are
green. Each filled sign-off names the reviewer, the scope reviewed,
and the date, and is mirrored in the Changelog row and the Risk
Report for that release.

## Appendix F: Compliance checklist (reviewer sign-off sheet)

Run top to bottom before merging a `SAFETY.md` change or cutting a
release. Every box must be checked or explicitly marked N/A with a
reason; an unchecked box blocks the release.

- [ ] C1–C5 capability procedure (§5) run: level pinned at `2`,
  gate green, threshold markers present, placement spot-checked,
  verdict written into the Risk Report.
- [ ] G1–G4 safeguards procedure (§6) run: S1–S5 re-verified
  (`test` + `audit` shards green, evidence links resolve), P1–P10
  still ticketed and unclaimed, no out-of-band safeguard claimed.
- [ ] F1–F5 follow-up procedure (§7) run: filled Risk Report copied
  from the template with evaluations, FAL verdict, real
  `coverage_date`/`published` dates, full commit SHA, ticketed Known
  gaps, explicit Redactions, and Attestation sections; heartbeat
  current (no gap over 6 months); `release-gate.sh code` green.
- [ ] Pause rule (§8) honoured: no gated capability (escrow,
  lending/borrowing, margin/yield, fiat/crypto bridges, compute
  marketplace, autonomous spending) outside allowlisted prose; any
  hit handled as Restrict with pause tag + `safety` issue + 7-day
  report, never merged around the gate.
- [ ] Governance (§9) honoured: correct PR tier applied; threshold
  changes carry external sign-off in Appendix E + Changelog + Risk
  Report; non-retaliation holds (no penalty for raising the alarm).
- [ ] Versioning and redline: `Version:` header equals the tag being
  cut (`release-gate.sh safety` green); Changelog row added newest
  first with diff + compare URL; `git verify-tag` passes on the
  safety tag (procedure: [verify-runbook.md](docs/safety/verify-runbook.md)).
- [ ] Imports, not copies: FAL definitions still owned by ADR-0004,
  domain terms by `CONTEXT.md`, argument by the safety case, harness
  by ADR-0006, cadence by `risk-reports.md` — this file points at
  them and restates nothing normatively.
