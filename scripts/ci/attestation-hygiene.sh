#!/usr/bin/env bash
# Usage: attestation-hygiene.sh <dir>
# Fails if any file under <dir> contains material that must never enter
# attested artifacts (ADR 0005): peer-identifying addresses (IPv4/IPv6
# literals, multiaddr locators) or secret key material. Summaries and
# digests pass; raw exploit detail and peer IPs fail loudly.
# Forbidden-material patterns mirror scripts/ci/release-gate.sh, with one
# documented exemption: loopback/unspecified bind literals (127.0.0.0/8,
# ::1, 0.0.0.0) are not peer-identifying — they name no remote peer — so
# localhost-bind documentation (e.g. docs/adr/0003) passes.
# Archives (*.tar.gz, *.tgz) are extracted into an isolated temp dir and
# their members scanned too: gzip hides member bytes from direct grep, so
# scanning only the compressed file would miss forbidden content inside.
# Unreadable archives fail closed (an unscannable bundle must not pass).
set -euo pipefail

dir="${1:?usage: attestation-hygiene.sh <dir>}"
[ -d "$dir" ] || { echo "attestation-hygiene: not a directory: $dir"; exit 1; }

IPV6_RE='(^|[^[:alnum:]:])(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|:((:[0-9A-Fa-f]{1,4}){1,7}|:))([^[:alnum:]:]|$)'

fail=0

# scan_file <path>: fail if <path> holds forbidden material. Grep reads
# via herestring (never `echo | grep -q` under pipefail: grep -q exits on
# first match, the SIGPIPE'd echo then fails the pipeline and the match
# is lost).
scan_file() {
  local f="$1"
  local stripped
  # Strip standalone loopback/unspecified literals before matching, so
  # localhost-bind documentation passes while real peer addresses fail.
  # Boundaries matter: 2001:db8::1 keeps its ::1 (preceded by hex), and
  # 192.168.127.1 keeps its 127.1 (preceded by a digit/dot).
  stripped="$(sed -E -e 's/(^|[^0-9.])(127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|0\.0\.0\.0)([^0-9.]|$)/\1\3/g' -e 's/(^|[^0-9A-Za-z:])(::1)([^0-9A-Za-z:]|$)/\1\3/g' "$f")"
  # Quads embedded in longer dotted runs (OIDs, version tuples) name no
  # host; placeholder /ip4/... multiaddrs name no peer either.
  if grep -qE '(^|[^0-9.])[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([^0-9.]|$)' <<< "$stripped"; then
    echo "attestation-hygiene: $f contains a peer-identifying IPv4 literal (loopback 127.* and 0.0.0.0 bind docs exempt; peer IPs stay internal-only)"
    fail=1
  fi
  if grep -qE "$IPV6_RE" <<< "$stripped"; then
    echo "attestation-hygiene: $f contains a peer-identifying IPv6 literal (loopback ::1 exempt; peer IPs stay internal-only)"
    fail=1
  fi
  if grep -qE '/ip[46]/[0-9A-Za-z]|/dns(4|6|addr)?/[0-9A-Za-z]' <<< "$stripped"; then
    echo "attestation-hygiene: $f contains a multiaddr locator with a real address (placeholders like /ip4/... and bare /dnsaddr pass; peer locators stay internal-only)"
    fail=1
  fi
  if grep -q 'PRIVATE KEY' "$f"; then
    echo "attestation-hygiene: $f contains secret key material"
    fail=1
  fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Plain files first; archives are covered via extraction below, where
# their members — not the compressed bytes — are scanned.
while IFS= read -r -d '' f; do
  case "$f" in *.tar.gz|*.tgz) continue;; esac
  scan_file "$f"
done < <(find "$dir" -type f -print0)

# Extract every archive (including archives nested inside archives) and
# scan the members. Extraction failure fails closed.
queue=()
while IFS= read -r -d '' a; do queue+=("$a"); done < <(find "$dir" -type f \( -name '*.tar.gz' -o -name '*.tgz' \) -print0)
n=0
while [ "${#queue[@]}" -gt 0 ]; do
  a="${queue[0]}"; queue=("${queue[@]:1}")
  d="$work/$n"; mkdir -p "$d"; n=$((n + 1))
  if ! tar -xzf "$a" -C "$d" 2>/dev/null; then
    echo "attestation-hygiene: $a is not a readable gzip tarball (fail-closed)"
    fail=1
    continue
  fi
  while IFS= read -r -d '' m; do
    case "$m" in
      *.tar.gz|*.tgz) queue+=("$m");;
      *) scan_file "$m";;
    esac
  done < <(find "$d" -type f -print0)
done

if [ "$fail" -ne 0 ]; then
  echo "attestation-hygiene: FAIL ($dir holds forbidden material)"
  exit 1
fi
echo "attestation-hygiene: PASS ($dir holds digests plus summaries only)"
