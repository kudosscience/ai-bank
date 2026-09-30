#!/usr/bin/env bash
# Usage: rekor-monitor.sh [--json entries.json | --check-attestation attestation.json]
# Watches our Sigstore signing identity for unauthorized Rekor entries.
# - Live mode (default): for every GitHub Release in this repo, downloads
#   its Sigstore bundle and re-verifies it against the repo identity. A
#   release whose bundle fails verification, or whose attestation pins a
#   commit no known tag contains, fails loudly so the safety-monitor
#   workflow can open a `safety`-labelled issue.
# - --json mode: checks a saved Rekor entry list offline (self-test and
#   reviewer replay): each entry must pin a commit contained in a known
#   tag (safety/v*, v*, pause/*), else FAIL.
# - --check-attestation mode: checks a saved `gh attestation verify
#   --format json` output offline (self-test seam for live mode): every
#   attestation's source commit must be contained in a known tag, else FAIL.
# Output is summaries only (UUID + identity + commit) — never payloads.
set -euo pipefail

REPO="${REPO:-kudosscience/clawbank}"

# check_entries <json-file>: every entry's commit must resolve to a tag
# in this clone; unknown or unpinned commits FAIL.
check_entries() {
  local file="$1"
  python3 - "$file" <<'EOF'
import json, subprocess, sys

path = sys.argv[1]
try:
    data = json.load(open(path))
except Exception as exc:
    print(f"rekor-monitor: cannot parse entries JSON: {exc}")
    sys.exit(2)

if isinstance(data, dict):
    items = list(data.items())
elif isinstance(data, list):
    items = [(e.get("uuid", f"index-{i}"), e) for i, e in enumerate(data)]
else:
    print("rekor-monitor: unexpected entries shape (want object or list)")
    sys.exit(2)

if not items:
    print("rekor-monitor: no entries found (log empty for this identity)")
    sys.exit(0)

known, unknown = 0, 0
for uuid, entry in items:
    commit = ""
    if isinstance(entry, dict):
        body = entry.get("body", {}) or {}
        spec = body.get("spec", {}) or {}
        commit = ((spec.get("data", {}) or {}).get("hash", {}) or {}).get("value", "") or entry.get("commit", "")
    if not commit:
        print(f"rekor-monitor: entry {uuid} carries no commit pin — cannot authorize (FAIL)")
        unknown += 1
        continue
    try:
        tags = subprocess.run(
            ["git", "tag", "--contains", commit],
            capture_output=True, text=True, check=False).stdout.split()
    except Exception:
        tags = []
    if any(t.startswith(("v", "safety/v", "pause/")) for t in tags):
        known += 1
    else:
        print(f"rekor-monitor: entry {uuid} pins unknown commit {commit} (no safety/v*, v*, or pause/* tag contains it)")
        unknown += 1

print(f"rekor-monitor: {known} authorized, {unknown} unauthorized")
sys.exit(1 if unknown else 0)
EOF
}

if [ "${1:-}" = "--json" ]; then
  check_entries "${2:?usage: rekor-monitor.sh --json <entries.json>}"
  exit $?
fi

# check_attestation_json <file>: every attestation in a saved
# `gh attestation verify --format json` output must pin a source commit
# contained in a known tag (safety/v*, v*, pause/*); else FAIL.
# Shares the known-tag policy with check_entries so live verification
# cannot pass an attestation for an untagged commit.
check_attestation_json() {
  local file="$1"
  python3 - "$file" <<'EOF'
import json, re, subprocess, sys

path = sys.argv[1]
try:
    data = json.load(open(path))
except Exception as exc:
    print(f"rekor-monitor: cannot parse attestation JSON: {exc}")
    sys.exit(2)

items = data if isinstance(data, list) else [data]
if not items:
    print("rekor-monitor: attestation JSON carries no attestations — cannot authorize (FAIL)")
    sys.exit(1)

sha_re = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$", re.IGNORECASE)
commit_keys = {"gitcommit", "sha1", "sha", "commit", "sourcerepositorydigest"}

def collect_commits(node, out):
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str) and k.lower() in commit_keys and sha_re.match(v):
                out.append(v.lower())
            else:
                collect_commits(v, out)
    elif isinstance(node, list):
        for v in node:
            collect_commits(v, out)

def tags_contain(commit):
    try:
        tags = subprocess.run(
            ["git", "tag", "--contains", commit],
            capture_output=True, text=True, check=False).stdout.split()
    except Exception:
        return False
    return any(t.startswith(("v", "safety/v", "pause/")) for t in tags)

known, unknown = 0, 0
for i, item in enumerate(items):
    vr = item.get("verificationResult", item) if isinstance(item, dict) else {}
    stmt = (vr.get("statement", {}) or {}) if isinstance(vr, dict) else {}
    pred = (stmt.get("predicate", {}) or {}) if isinstance(stmt, dict) else {}
    cert = ((vr.get("signature", {}) or {}).get("certificate", {}) or {}) if isinstance(vr, dict) else {}
    candidates = []
    collect_commits(pred, candidates)
    collect_commits(cert, candidates)
    # Minimal seam shape for tests and forward-compat: top-level commit.
    if isinstance(item, dict) and isinstance(item.get("commit"), str) and sha_re.match(item["commit"]):
        candidates.append(item["commit"].lower())
    # Deduplicate while preserving order.
    seen = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]
    pinned = next((c for c in candidates if tags_contain(c)), None)
    if pinned:
        known += 1
    else:
        if candidates:
            print(f"rekor-monitor: attestation index-{i} pins unknown commit {candidates[0]} (no safety/v*, v*, or pause/* tag contains it)")
        else:
            print(f"rekor-monitor: attestation index-{i} carries no commit pin — cannot authorize (FAIL)")
        unknown += 1

print(f"rekor-monitor: {known} authorized, {unknown} unauthorized")
sys.exit(1 if unknown else 0)
EOF
}

if [ "${1:-}" = "--check-attestation" ]; then
  check_attestation_json "${2:?usage: rekor-monitor.sh --check-attestation <attestation.json>}"
  exit $?
fi

# Live mode: re-verify every release's attestation bundle.
if ! command -v gh >/dev/null 2>&1; then
  echo "rekor-monitor: gh CLI not found — cannot query releases (reachability gap, not a forgery signal)"
  exit 0
fi
# Paginate through all releases: a fixed --limit window would silently
# omit older releases from attestation verification.
# A failed query is a reachability gap (warn, exit 0), distinct from an
# actually-empty release list (PASS): never collapse errors into PASS.
if ! tags="$(gh api --paginate "repos/$REPO/releases?per_page=100" --jq '.[].tag_name' 2>/dev/null)"; then
  echo "rekor-monitor: cannot list releases (reachability gap, not a forgery signal)"
  exit 0
fi
if [ -z "$tags" ]; then
  echo "rekor-monitor: no releases published yet — nothing to cross-check (PASS)"
  exit 0
fi
fail=0
while IFS= read -r tag; do
  [ -n "$tag" ] || continue
  dir="$(mktemp -d)"
  if gh release download "$tag" --repo "$REPO" -D "$dir" >/dev/null 2>&1; then
    while IFS= read -r -d '' f; do
      case "$f" in *.jsonl|*SHA256SUMS) continue;; esac
      verify_out="$(mktemp)"
      if gh attestation verify "$f" --repo "$REPO" --format json >"$verify_out" 2>/dev/null; then
        if check_attestation_json "$verify_out" >/dev/null 2>&1; then
          echo "rekor-monitor: $tag/$(basename "$f") attestation OK (commit pinned to known tag)"
        else
          echo "rekor-monitor: $tag/$(basename "$f") attestation VALID but pins no known tag commit (possible forgery)"
          fail=1
        fi
      else
        echo "rekor-monitor: $tag/$(basename "$f") attestation FAILED (possible forgery)"
        fail=1
      fi
      rm -f "$verify_out"
    done < <(find "$dir" -type f -print0)
  else
    echo "rekor-monitor: cannot download $tag (reachability gap, not a forgery signal)"
  fi
  rm -rf "$dir"
done <<< "$tags"
[ "$fail" -eq 0 ] && echo "rekor-monitor: PASS (all release attestations verify)"
exit "$fail"
