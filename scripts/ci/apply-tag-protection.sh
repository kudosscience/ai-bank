#!/usr/bin/env bash
# Usage: apply-tag-protection.sh [--dry-run]
# Creates (or prints, with --dry-run) the GitHub ruleset that protects
# the safety tag pattern: safety/v* and pause/* require signed tags.
# No `creation` rule on purpose: creation restricts who may create matching
# tags to bypass actors (of which this payload defines none), so it would
# block maintainers from cutting new safety/pause tags. Update, deletion,
# and signature requirements are what the gate needs.
# Needs a token with admin:read/write on the repo (maintainer one-time).
# Safe to re-run: skips creation when an equivalent ruleset already exists.
set -euo pipefail

REPO="${REPO:-kudosscience/clawbank}"
DRY_RUN="${1:-}"

ruleset() {
  cat <<'JSON'
{
  "name": "safety-tags-require-signatures",
  "target": "tag",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/safety/v*", "refs/tags/pause/*"],
      "exclude": []
    }
  },
  "rules": [
    {"type": "update"},
    {"type": "deletion"},
    {"type": "required_signatures"}
  ]
}
JSON
}

if [ "$DRY_RUN" = "--dry-run" ]; then
  ruleset
  exit 0
fi

existing="$(gh api "repos/${REPO}/rulesets" --jq '.[].name' 2>/dev/null || true)"
if echo "$existing" | grep -qx 'safety-tags-require-signatures'; then
  echo "apply-tag-protection: ruleset already exists (nothing to do)"
  exit 0
fi
ruleset | gh api "repos/${REPO}/rulesets" --input - --jq '.id' 2>&1
echo "apply-tag-protection: ruleset created for safety/v* and pause/* (signed tags required)"
