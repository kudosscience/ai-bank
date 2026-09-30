# Security policy

Report safety or security concerns as a GitHub Issue with the `safety`
label — no prior permission needed, and good-faith false alarms are
welcomed under the non-retaliation commitment in `SAFETY.md` §9.

- Safety (thresholds, pause rule, risk reports): open an issue with the
  `safety` label, per [ADR-0005](docs/adr/0005-safety-doc-pattern.md).
  Emergency pause needs no permission: cut
  `git tag -s pause/YYYY-MM-DD` first, then file the issue and the
  7-day full report (see `SAFETY.md` §8.3 and
  `docs/safety/verify-runbook.md`).
- Security-sensitive material (exploit detail, peer-identifying data,
  key material): do **not** post it publicly. Open a minimal `safety`
  issue describing the category only, and the maintainer will arrange a
  private channel. Public notes carry summaries and digests by rule —
  raw exploit detail and peer IPs stay internal-only
  (see `docs/safety/risk-reports.md`).

Verification (tags, releases, attestations):
`docs/safety/verify-runbook.md`. Maintainer keys:
`docs/safety/MAINTAINER_PUBKEYS.asc` and `.github/trusted-keys/`.
