# Verify runbook: tags, redline, and release attestation end to end

Independent verification without trusting any server we run: maintainer
keys are in-repo, safety tags are signed, releases carry Sigstore/Rekor
attestation, and every step below runs locally. Follows
[ADR-0005](../adr/0005-safety-doc-pattern.md); tag pattern `safety/v*`
(plus emergency `pause/YYYY-MM-DD`); provenance via GitHub's
Sigstore-backed attestation (public Rekor).

## 0. One-time setup

```sh
# Trust the maintainer keys pinned in-repo (GPG path):
gpg --import docs/safety/MAINTAINER_PUBKEYS.asc
gpg --fingerprint AA5AEB7313B2A916
# expect: D23D 4D17 9B4C 1D45 25BB A1EF AA5A EB73 13B2 A916

# ... or the SSH path (tags cut with gpg.format=ssh):
git config gpg.ssh.allowedSignersFile .github/trusted-keys/allowed_signers
```

Tag protection (maintainer, one-time, GitHub UI or script): the
`safety/v*` and `pause/*` patterns require signed tags. To apply via API:

```sh
bash scripts/ci/apply-tag-protection.sh
```

The release workflow enforces the same property in CI: the `verify-tag`
job tries `git verify-tag` (OpenPGP) then
`git -c gpg.format=ssh verify-tag` (SSH) on every pushed tag, so an unsigned
`safety/v*` or `pause/*` tag fails the build even if the ruleset was
never applied.

## 1. Verify the safety tag

```sh
git fetch --tags
# Tags may be cut with either GPG or SSH: try OpenPGP first, then SSH
# (git verify-tag defaults to OpenPGP and rejects SSH signatures
# without gpg.format=ssh).
if git verify-tag safety/v0.2.0 2>/dev/null; then
  echo "GPG-signed tag: prints Good signature ... AA5AEB7313B2A916"
else
  git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=.github/trusted-keys/allowed_signers \
    verify-tag safety/v0.2.0
  # SSH-signed tag prints:
  #   Good "git" signature for 45144290+kudosscience@users.noreply.github.com with ED25519 key SHA256:av7CIaWccVRNZkIRVrYNEHMwNZ0GbzRvweEhHZSSMHo
fi
git show safety/v0.2.0 --no-patch --format='%T %aN'
# %T pins the tagged tree; cross-check it against the Risk Report's
# evaluated commit and the Changelog redline in step 2.
```

## 2. Reproduce the Changelog redline

Each `SAFETY.md` Appendix D row is a diff between the signed tags it
names. Reproduce the latest entry:

```sh
bash scripts/ci/release-gate.sh safety 0.2.0
git show safety/v0.2.0:SAFETY.md | grep -m1 -E '^Version:'
git diff safety/v0.1.0..safety/v0.2.0 -- SAFETY.md | head -n 100
# compare URL: https://github.com/kudosscience/clawbank/compare/safety/v0.1.0...safety/v0.2.0
```

If the diff does not match the Changelog row, the row is wrong — file a
`safety`-labelled issue (see `SECURITY.md`).

## 3. Verify the release artifact (online)

Every `v*` release publishes a docs bundle plus `SHA256SUMS` under the
GitHub Release, with Sigstore/Rekor provenance from
`actions/attest-build-provenance` (subject = artifact digest; see
`.github/workflows/release.yml`).

```sh
TAG=v0.2.0  # or the release under review
gh release download "$TAG" -p 'clawbank-docs-*' -p SHA256SUMS
sha256sum -c SHA256SUMS
gh attestation verify "clawbank-docs-${TAG}.tar.gz" --repo kudosscience/clawbank
```

What the attestation proves: the digest-named file was built by this
repo's `release.yml` at the tagged commit (SLSA provenance: source URI +
builder ID + commit SHA, Rekor entry with SCT + Signed Tree Head).
What it does NOT contain: the note's verdict stays in the Risk Report
inside the bundle; raw exploit detail and peer-identifying data are
forbidden in attested artifacts by rule — the `hygiene` job
(`scripts/ci/attestation-hygiene.sh`) fails the release if the bundle
holds a real peer address, multiaddr locator, or key block (loopback
bind docs, OIDs, and `/ip4/...` placeholders pass; they name no peer).

## 4. Verify fully offline (bundle + trust root, no hosted verifier)

Fetch once while online, verify forever offline — no hosted verifier
needed after the fetch:

```sh
TAG=v0.2.0
FILE="clawbank-docs-${TAG}.tar.gz"
gh attestation download "$FILE" --repo kudosscience/clawbank
# writes sha256-<digest>.jsonl (Linux keeps the colon: sha256:<digest>.jsonl); normalize it:
mv sha256*.jsonl /tmp/attest.jsonl
gh attestation trusted-root > /tmp/trusted-root.jsonl
gh attestation verify "$FILE" --repo kudosscience/clawbank \
  --bundle /tmp/attest.jsonl --custom-trusted-root /tmp/trusted-root.jsonl
# or without gh, with cosign/rekor-cli against the same bundle:
# cosign verify-blob --bundle /tmp/attest.jsonl "$FILE"
```

Keep `/tmp/attest.jsonl` + `/tmp/trusted-root.jsonl` with the artifact:
together they re-verify offline from bundle plus trust root.

## 5. Monitor for forgeries

`.github/workflows/safety-monitor.yml` (daily cron + manual dispatch)
watches our signing identity for unauthorized Rekor entries via
`scripts/ci/rekor-monitor.sh`: it paginates through every GitHub Release,
re-verifies each artifact's Sigstore attestation, and additionally requires
the attested source commit to be contained in a known signed tag
(`safety/v*`, `v*`, `pause/*`). It fails (opening a `safety` issue on schedule)
if any attestation stops verifying or pins a commit outside a known release tag. To run the check
locally:

```sh
bash scripts/ci/rekor-monitor.sh
```

If verification fails anywhere above, treat it as a safety event: cut no
new tags, open a `safety`-labelled issue per `SECURITY.md`, and — if a
FAL-3-gated capability or forged attestation is involved — cut an
emergency `git tag -s pause/YYYY-MM-DD` first (§8.3).
