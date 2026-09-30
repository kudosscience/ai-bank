#!/usr/bin/env bash
# Self-test for scripts/ci/rekor-monitor.sh --json (TDD seam for Docs 03).
# Run: bash scripts/ci/tests/test-rekor-monitor.sh
set -euo pipefail

script="scripts/ci/rekor-monitor.sh"
pass=0
fail=0

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Fixture 1: empty log passes.
echo '{}' > "$tmp/empty.json"
if bash "$script" --json "$tmp/empty.json" >/dev/null 2>&1; then pass=$((pass + 1)); else echo "FAIL: empty log should pass"; fail=$((fail + 1)); fi

# Fixture 2: entry pinning a commit inside a known safety tag passes.
# safety/v0.2.0 exists once Docs 03 cuts it; fall back to HEAD lookup so
# the fixture tracks whichever tagged commit is available.
known_tag="$(git tag -l 'safety/v*' | sort -V | tail -n1 || true)"
if [ -n "$known_tag" ]; then
  known_sha="$(git rev-list -n1 "$known_tag")"
  python3 - "$tmp/known.json" "$known_sha" <<'EOF'
import json, sys
path, sha = sys.argv[1], sys.argv[2]
json.dump({"0000000000000000000000000000000000000000000000000000000000000000":
  {"body": {"spec": {"data": {"hash": {"value": sha}}}}}}, open(path, "w"))
EOF
  if bash "$script" --json "$tmp/known.json" >/dev/null 2>&1; then pass=$((pass + 1)); else echo "FAIL: tagged commit should pass"; fail=$((fail + 1)); fi
else
  echo "SKIP: no safety/v* tag yet (tagged-commit fixture needs one)"
fi

# Fixture 3: entry pinning an unknown commit fails. A synthetic SHA can
# never be contained in a tag, so this is deterministic.
python3 - "$tmp/unknown.json" <<'EOF'
import json, sys
json.dump({"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff":
  {"body": {"spec": {"data": {"hash": {"value": "ffffffffffffffffffffffffffffffffffffffff"}}}}}}, open(sys.argv[1], "w"))
EOF
if bash "$script" --json "$tmp/unknown.json" >/dev/null 2>&1; then echo "FAIL: unknown commit should fail"; fail=$((fail + 1)); else pass=$((pass + 1)); fi

# Fixture 4: entry with no commit pin fails.
echo '{"abc123": {"body": {"spec": {}}}}' > "$tmp/nopin.json"
if bash "$script" --json "$tmp/nopin.json" >/dev/null 2>&1; then echo "FAIL: unpinned entry should fail"; fail=$((fail + 1)); else pass=$((pass + 1)); fi

# Fixture 5: attestation JSON pinning a tagged commit passes
# (--check-attestation reuses the live-mode commit-pin check offline).
if [ -n "${known_sha:-}" ]; then
  python3 - "$tmp/att-known.json" "$known_sha" <<'EOF'
import json, sys
path, sha = sys.argv[1], sys.argv[2]
json.dump([{"verificationResult": {"statement": {"predicate": {
  "buildDefinition": {"resolvedDependencies": [{"digest": {"gitCommit": sha}}]}}}}}], open(path, "w"))
EOF
  if bash "$script" --check-attestation "$tmp/att-known.json" >/dev/null 2>&1; then pass=$((pass + 1)); else echo "FAIL: attestation pinning tagged commit should pass"; fail=$((fail + 1)); fi
else
  echo "SKIP: no known SHA for attestation fixture"
fi

# Fixture 6: attestation JSON pinning an unknown commit fails.
python3 - "$tmp/att-unknown.json" <<'EOF'
import json, sys
json.dump([{"verificationResult": {"statement": {"predicate": {
  "buildDefinition": {"resolvedDependencies": [{"digest": {"gitCommit": "ffffffffffffffffffffffffffffffffffffffff"}}]}}}}}], open(sys.argv[1], "w"))
EOF
if bash "$script" --check-attestation "$tmp/att-unknown.json" >/dev/null 2>&1; then echo "FAIL: attestation pinning unknown commit should fail"; fail=$((fail + 1)); else pass=$((pass + 1)); fi

# Fixture 7: attestation JSON with no commit pin fails.
echo '[{"verificationResult": {"statement": {"predicate": {}}}}]' > "$tmp/att-nopin.json"
if bash "$script" --check-attestation "$tmp/att-nopin.json" >/dev/null 2>&1; then echo "FAIL: unpinned attestation should fail"; fail=$((fail + 1)); else pass=$((pass + 1)); fi

# Fixture 8: live mode must paginate all releases (no fixed --limit 100).
if grep -q -- '--limit 100' "$script"; then echo "FAIL: live mode still uses fixed --limit 100 (misses releases beyond window)"; fail=$((fail + 1)); else pass=$((pass + 1)); fi
if grep -q -- '--paginate' "$script"; then pass=$((pass + 1)); else echo "FAIL: live mode should paginate releases"; fail=$((fail + 1)); fi

# Fixture 9: live mode must enforce the known-tag commit-pin check on top
# of `gh attestation verify` (an attestation for an untagged commit must FAIL).
if grep -q 'check_attestation_json "$verify_out"' "$script" && grep -q -- '--format json' "$script"; then pass=$((pass + 1)); else echo "FAIL: live mode should check attestation commit pin against known tags"; fail=$((fail + 1)); fi

# Fixture 10: a failed release query must not report PASS. The tags query
# must check the exit status separately (reachability gap warning, exit 0)
# instead of swallowing errors with `|| true` into the empty-list PASS.
if grep -q 'if ! tags=' "$script"; then pass=$((pass + 1)); else echo "FAIL: live mode should distinguish release-query failure from empty list"; fail=$((fail + 1)); fi

echo "rekor-monitor self-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
